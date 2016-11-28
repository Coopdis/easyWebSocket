// based on https://github.com/dangrie158/ESP-8266-WebSocket

#include <Arduino.h>

extern "C" {
#include "user_interface.h"
#include "espconn.h"

#include "sha1.h"
#include "base64.h"
}
#include "easyWebSocket.h"

espconn webSocketConn;
esp_tcp webSocketTcp;

static void (*wsOnConnectionCallback)(void);
static void (*wsOnMessageCallback)( char *payloadData );

static WSConnection wsConnections[WS_MAXCONN];

//***********************************************************************
void ICACHE_FLASH_ATTR webSocketInit( void ) {
    webSocketConn.type = ESPCONN_TCP;
    webSocketConn.state = ESPCONN_NONE;
    webSocketConn.proto.tcp = &webSocketTcp;
    webSocketConn.proto.tcp->local_port = WEB_SOCKET_PORT;
    espconn_regist_connectcb(&webSocketConn, webSocketConnectCb);

    espconn_set_opt( &webSocketConn, ESPCONN_NODELAY );  // remove nagle for low latency

    sint8 ret = espconn_accept(&webSocketConn);
    if ( ret == 0 )
        webSocketDebug("webSocket server established on port %d\n", WEB_SOCKET_PORT );
    else
        webSocketDebug("webSocket server on port %d FAILED ret=%d\n", WEB_SOCKET_PORT, ret);

    return;
}

//***********************************************************************
void ICACHE_FLASH_ATTR webSocketSetReceiveCallback( void (*onMessage)( char *payloadData) ) {
    wsOnMessageCallback = onMessage;
}

//***********************************************************************
void ICACHE_FLASH_ATTR webSocketSetConnectionCallback( void (*onConnection)(void) ) {
    wsOnConnectionCallback = onConnection;
}

//***********************************************************************
void ICACHE_FLASH_ATTR webSocketConnectCb(void *arg) {
  struct espconn *connection = (espconn *)arg;

  webSocketDebug("\n\nmeshWebSocket received connection !!!\n");

    // set time out for this connection in seconds
    espconn_regist_time( connection, 120, 1);

  //find an empty slot
  uint8_t slotId = 0;
  while (wsConnections[slotId].connection != NULL && wsConnections[slotId].status != STATUS_CLOSED && slotId < WS_MAXCONN) {
    slotId++;
  }

  webSocketDebug("websocketConnectCb slotId=%d\n", slotId);


  if (slotId >= WS_MAXCONN) {
    //no more free slots, close the connection
    webSocketDebug("No more free slots for WebSockets!\n");
    espconn_disconnect(connection);
    return;
  }

  //  webSocketDebug("websocketConnectCb2\n");

  WSConnection wsConnection;
  wsConnection.status = STATUS_UNINITIALISED;
  wsConnection.connection = connection;
  wsConnection.onMessage = wsOnMessageCallback;
  wsConnections[slotId] = wsConnection;

  //  webSocketDebug("websocketConnectCb3\n");

  espconn_regist_recvcb(connection, webSocketRecvCb);
  espconn_regist_sentcb(connection, webSocketSentCb);
  espconn_regist_reconcb(connection, webSocketReconCb);
  espconn_regist_disconcb(connection, webSocketDisconCb);

  //  webSocketDebug("leaving websocketConnectCb\n");
}

//***********************************************************************
void ICACHE_FLASH_ATTR webSocketRecvCb(void *arg, char *data, unsigned short len) {
  espconn *esp_connection = (espconn*)arg;

  //received some data from webSocket connection
  //webSocketDebug("In webSocketRecvCb\n");
  //  webSocketDebug("webSocket recv--->%s<----\n", data);

  WSConnection *wsConnection = getWsConnection(esp_connection);
  if (wsConnection == NULL) {
    webSocketDebug("webSocket Heh?\n");
    return;
  }

  //get the first occurrence of the key identifier
  char *key = os_strstr(data, WS_KEY_IDENTIFIER);

  //  webSocketDebug("key-->%s<--\n", key );

  if (key != NULL) {
    // ------------------------ Handle the Handshake ------------------------
    //    webSocketDebug("In Handle the Handshake\n");
    //Skip the identifier (that contains the space already)
    key += os_strlen(WS_KEY_IDENTIFIER);

    //   webSocketDebug("keynow-->%s<--\n", key);

    //the key ends at the newline
    char *endSequence = os_strstr(key, HTML_HEADER_LINEEND);
    //    webSocketDebug("endSequency-->%s<--\n", endSequence);

    if (endSequence != NULL) {
      int keyLastChar = endSequence - key;
      //we can throw away all the other data, only the key is interesting
      key[keyLastChar] = '\0';
      //      webSocketDebug("keyTrimmed-->%s<--\n", key);

      char acceptKey[100];
      createWsAcceptKey(key, acceptKey, 100);

      //     webSocketDebug("acceptKey-->%s<--\n", acceptKey);

      //now construct our message and send it back to the client
      char responseMessage[strlen(WS_RESPONSE) + 100];
      os_sprintf(responseMessage, WS_RESPONSE, acceptKey);

      //      webSocketDebug("responseMessage-->%s<--\n", responseMessage);

      //send the response
      espconn_sent(esp_connection, (uint8_t *)responseMessage, strlen(responseMessage));
      wsConnection->status = STATUS_OPEN;

      //call the connection callback
      if (wsOnConnectionCallback != NULL) {
        //       webSocketDebug("Handle the Handshake 5\n");
        wsOnConnectionCallback();
      }
    }
  } else {
    // ------------------------ Handle a Frame ------------------------
    //    webSocketDebug("In Handle a Frame\n");

    WSFrame frame;
    parseWsFrame(data, &frame);

    if (frame.isMasked) {
      unmaskWsPayload(frame.payloadData, frame.payloadLength, frame.maskingKey);
    } else {
      //we are the server, and need to shut down the connection
      //if we receive an unmasked packet
      //      webSocketDebug("frame.isMasked=false closing connection\n");
      closeWsConnection(wsConnection);
      return;
    }

//    webSocketDebug("frame.payloadData-->%s<--\n", frame.payloadData);

    if (frame.opcode == OPCODE_PING) {
      //      webSocketDebug("frame.opcode=OPCODE_PING\n");
      sendWsMessage(wsConnection, frame.payloadData, frame.payloadLength, FLAG_FIN | OPCODE_PONG);
      return;
    }

    if (frame.opcode == OPCODE_CLOSE) {
      //gracefully shut down the connection
      //      webSocketDebug("frame.opcode=OPCODE_CLOSE, closeing connection\n");
      closeWsConnection(wsConnection);
      return;
    }

    if (wsConnection->onMessage != NULL) {
      wsConnection->onMessage(frame.payloadData);
    }
  }
  //  webSocketDebug("Leaving webSocketRecvCb\n");
}

//***********************************************************************
static void ICACHE_FLASH_ATTR unmaskWsPayload(char *maskedPayload,
                                              uint32_t payloadLength,
                                              uint32_t maskingKey) {
  //the algorith described in IEEE RFC 6455 Section 5.3
  //TODO: this should decode the payload 4-byte wise and do the remainder afterwards
  for (int i = 0; i < payloadLength; i++) {
    int j = i % 4;
    maskedPayload[i] = maskedPayload[i] ^ ((uint8_t *)&maskingKey)[j];
  }
}

//***********************************************************************
static void ICACHE_FLASH_ATTR parseWsFrame(char *data, WSFrame *frame) {
  frame->flags = (*data) & FLAGS_MASK;
  frame->opcode = (*data) & OPCODE_MASK;
  //next byte
  data += 1;
  frame->isMasked = (*data) & IS_MASKED;
  frame->payloadLength = (*data) & PAYLOAD_MASK;

  //next byte
  data += 1;

  if (frame->payloadLength == 126) {
    os_memcpy(&frame->payloadLength, data, sizeof(uint16_t));
    data += sizeof(uint16_t);
  } else if (frame->payloadLength == 127) {
    os_memcpy(&frame->payloadLength, data, sizeof(uint64_t));
    data += sizeof(uint64_t);
  }

  if (frame->isMasked) {
    os_memcpy(&frame->maskingKey, data, sizeof(uint32_t));
    data += sizeof(uint32_t);
  }

  frame->payloadData = data;
}

//***********************************************************************
WSConnection *ICACHE_FLASH_ATTR getWsConnection(struct espconn *connection) {
//  webSocketDebug("In getWsConnecition\n");
  for (int slotId = 0; slotId < WS_MAXCONN; slotId++) {
//    webSocketDebug("slotId=%d, ws.conn*=%x, espconn*=%x<--  ", slotId, wsConnections[slotId].connection, connection);

    //    webSocketDebug("ws.connIP=%d.%d.%d.%d espconnIP=%d.%d.%d.%d --- ", IP2STR( wsConnections[slotId].connection->proto.tcp->remote_ip), IP2STR( connection->proto.tcp->remote_ip) );
//    webSocketDebug("ws.connIP=%x espconnIP=%x\n", *(uint32_t*)wsConnections[slotId].connection->proto.tcp->remote_ip, *(uint32_t*)connection->proto.tcp->remote_ip ) ;

    //   if (wsConnections[slotId].connection == connection) {
    if (*(uint32_t*)wsConnections[slotId].connection->proto.tcp->remote_ip == *(uint32_t*)connection->proto.tcp->remote_ip ) {
 //     webSocketDebug("Leaving getWsConnecition slotID=%d\n", slotId);
      return wsConnections + slotId;
    }
  }

//  webSocketDebug("Leaving getWsConnecition w/ NULL\n");
  return NULL;
}

//***********************************************************************
static int ICACHE_FLASH_ATTR createWsAcceptKey(const char *key, char *buffer, int bufferSize) {
  sha1nfo s;

  char concatenatedBuffer[512];
  concatenatedBuffer[0] = '\0';
  //concatenate the key and the GUID
  os_strcat(concatenatedBuffer, key);
  os_strcat(concatenatedBuffer, WS_GUID);

  //build the sha1 hash
  sha1_init(&s);
  sha1_write(&s, concatenatedBuffer, strlen(concatenatedBuffer));
  uint8_t *hash = sha1_result(&s);

  return base64_encode(20, hash, bufferSize, buffer);
}

//***********************************************************************
void ICACHE_FLASH_ATTR closeWsConnection(WSConnection * connection) {
  //  webSocketDebug("In closeWsConnection\n");

  char closeMessage[CLOSE_MESSAGE_LENGTH] = CLOSE_MESSAGE;
  espconn_sent(connection->connection, (uint8_t *)closeMessage, sizeof(closeMessage));
  connection->status = STATUS_CLOSED;
  return;
}

//***********************************************************************
void ICACHE_FLASH_ATTR broadcastWsMessage(const char *payload, uint32_t payloadLength, uint8_t options) {
    //webSocketDebug("broadcastWsMessage-->%s<-- payloadLength=%d\n", payload, payloadLength);
    for (int slotId = 0; slotId < WS_MAXCONN; slotId++) {
        WSConnection connection = wsConnections[slotId];
        if (connection.connection != NULL && connection.status == STATUS_OPEN) {
            sendWsMessage(&connection, payload, payloadLength, options);
        }
    }
}

//***********************************************************************
uint16_t ICACHE_FLASH_ATTR countWsConnections( void ) {
    uint16_t count = 0;
    for (int slotId = 0; slotId < WS_MAXCONN; slotId++) {
        WSConnection connection = wsConnections[slotId];
        if (connection.connection != NULL && connection.status == STATUS_OPEN) {
            count++;
        }
    }
    return count;
}

//***********************************************************************
void ICACHE_FLASH_ATTR sendWsMessage(WSConnection *connection,
                                     const char *payload,
                                     uint32_t payloadLength,
                                     uint8_t options) {

  webSocketDebug("sendWsMessage-->%s<-- payloadLength=%d\n", payload,payloadLength);

  uint8_t payloadLengthField[9];
  uint8_t payloadLengthFieldLength = 0;

  if (payloadLength > ((1 << 16) - 1)) {
    payloadLengthField[0] = 127;
    // os_memcpy(payloadLengthField + 1, &payloadLength, sizeof(uint32_t));
    // payloadLengthFieldLength = sizeof(uint32_t) + 1;
    for (int i =9; i>0; i--){
        uint8_t b = (payloadLength >>((i-1) *8)) & 0xff;
        os_memcpy(payloadLengthField +(10 -i), &b, sizeof(uint8_t));
    }
    payloadLengthFieldLength = 9;
  } else if (payloadLength > 125) { //((1 << 8) - 1)
    payloadLengthField[0] = 126;

    for (int i =2; i>0; i--){
        uint8_t b = (payloadLength >>((i-1) *8)) & 0xff;
        os_memcpy(payloadLengthField +(3 -i), &b, sizeof(uint8_t));
    }
    payloadLengthFieldLength = 3;
  } else {
    payloadLengthField[0] = payloadLength;
    payloadLengthFieldLength = 1;
  }

  // webSocketDebug("%d %d %d %d %d %d %d %d %d\n", payloadLengthField[0], payloadLengthField[1], payloadLengthField[2], payloadLengthField[3], payloadLengthField[4], payloadLengthField[5], payloadLengthField[6],payloadLengthField[7], payloadLengthField[8] );
  // webSocketDebug("%d\n", payloadLengthFieldLength);

  uint64_t maximumPossibleMessageSize = 14 + payloadLength; //14 bytes is the biggest frame header size
  char message[maximumPossibleMessageSize];
  message[0] = FLAG_FIN | options;

  os_memcpy(message + 1, &payloadLengthField, payloadLengthFieldLength);
  os_memcpy(message + 1 + payloadLengthFieldLength, payload, strlen(payload));

  // webSocketDebug("message -> %s size -> %d \n", message, payloadLength + 1 + payloadLengthFieldLength);

  while (true) {
    webSocketDebug("espconn_state -> %d \n", webSocketConn.state);
    if (webSocketConn.state != ESPCONN_WAIT) { delay(1); } else { break; }
  }

  int result = espconn_sent(connection->connection, (uint8_t *)&message, payloadLength + 1 + payloadLengthFieldLength);

  webSocketDebug("sendMessageResult -> %d \n", result);

  //////////////

  // uint8_t mask[4];
  // uint32_t size = payloadLength;
  //
  // uint64_t maximumPossibleMessageSize = 14 + size; //14 bytes is the biggest frame header size
  // char message[maximumPossibleMessageSize];
  //
  // // Opcode; final fragment
  // message[0] = FLAG_FIN | options;
  //
  // // NOTE: no support for > 16-bit sized messages
  // int i = 0;
  // if (size > 125) {
  //     message[1] = WS_SIZE16 | WS_MASK;
  //     message[2] = (uint8_t) (size >> 8);
  //     message[3] = (uint8_t) (size & 0xFF);
  //     i = 3;
  // } else {
  //     message[1] = (uint8_t) size | WS_MASK;
  //     i = 1;
  // }
  //
  // // mask[0] = random(0, 256);
  // // mask[1] = random(0, 256);
  // // mask[2] = random(0, 256);
  // // mask[3] = random(0, 256);
  // //
  // // message[i+1] = mask[0];
  // // message[i+2] = mask[1];
  // // message[i+3] = mask[2];
  // // message[i+4] = mask[3];
  //
  // int payloadSize = 0;
  // for (int j=0; j<size; ++j) {
  //     message[i+j+1] = payload[j]; //^ mask[j % 4];
  //     payloadSize = i+j+1;
  // }
  //
  // espconn_sent(connection->connection, (uint8_t *)&message, payloadSize);

}

//***********************************************************************
void ICACHE_FLASH_ATTR webSocketSentCb(void *arg) {
  //data sent successfully
  //webSocketDebug("webSocket sent cb \r\n");
  struct espconn *requestconn = (espconn *)arg;
  //  espconn_disconnect( requestconn );
}

/***********************************************************************/
void ICACHE_FLASH_ATTR webSocketDisconCb(void *arg) {
  espconn *esp_connection = (espconn*)arg;

  WSConnection *wsConn = getWsConnection( esp_connection);
  if ( wsConn != NULL ) {
    wsConn->status = STATUS_CLOSED;
    webSocketDebug("Leaving webSocket_server_discon_cb found\n");
    return;
  }

  webSocketDebug("Leaving webSocket_server_discon_cb  didn't find\n");
  return;
}

/***********************************************************************/
void ICACHE_FLASH_ATTR webSocketReconCb(void *arg, sint8 err) {
  webSocketDebug("In webSocket_server_recon_cb err=%d\n", err );
}
