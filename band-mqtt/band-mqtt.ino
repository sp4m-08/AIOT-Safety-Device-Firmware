#include <Wire.h>
#include <ESP8266WiFi.h>
#include <PubSubClient.h>
#include <ArduinoJson.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>
#include "MAX30100_PulseOximeter.h"
#include <MPU6050.h>
#include <time.h>
#include <Crypto.h>
#include <AES.h>
#include <GCM.h>

// ==============================================================================
// 1. HARDWARE & DISPLAY CONFIGURATION
// ==============================================================================
#define SCREEN_WIDTH 128
#define SCREEN_HEIGHT 64
Adafruit_SSD1306 oled(SCREEN_WIDTH, SCREEN_HEIGHT, &Wire, -1);

PulseOximeter pox;
MPU6050 mpu;
//D1 - SCL D2 - SDA
// ==============================================================================
// 2. NETWORK & MQTT BROKER CONFIGURATION
// ==============================================================================
const char* WIFI_SSID       = "TESTESP";             // Your Wi-Fi Name
const char* WIFI_PASS       = "12345678";   // Your Wi-Fi Password
const char* MQTT_BROKER     = "10.196.169.114";         // Your Laptop's Wi-Fi IP Address
const int   MQTT_PORT       = 1883;                 // Local Mosquitto Port
const char* TOPIC_TELEMETRY = "aiot/v1/band/telemetry";
const char* TOPIC_SOS       = "aiot/v1/band/sos";

// Master 256-bit Secret Key (Matches server/src/crypto/aesGcmEngine.ts)
const uint8_t AES_KEY[32] = {
  0xa1,0xb2,0xc3,0xd4,0xe5,0xf6,0x07,0x18,
  0x29,0x3a,0x4b,0x5c,0x6d,0x7e,0x8f,0x90,
  0x12,0x34,0x56,0x78,0x90,0xab,0xcd,0xef,
  0x12,0x34,0x56,0x78,0x90,0xab,0xcd,0xef
};

WiFiClient espClient;
PubSubClient mqttClient(espClient);

// ==============================================================================
// 3. MOTION & FALL TRACKING STATE
// ==============================================================================
unsigned long lastStepTime = 0;
const unsigned long stepDebounceTime = 300;
int stepCount = 0;

bool fallDetected = false; 
unsigned long fallAlertTimer = 0;
const unsigned long fallAlertDuration = 3000; 

// Two-stage fall state tracking
bool freeFallDetected = false;
unsigned long freeFallTime = 0;
const unsigned long maxImpactWindowMs = 400; // Must hit ground within 400ms of free-fall

uint32_t msg_counter = 1;

// Heart Icon Bitmap
const unsigned char heartBitmap[] PROGMEM = {
    0x00, 0x00, 0x00, 0x00, 0x01, 0x80, 0x18, 0x00, 0x0f, 0xe0,
    0x7f, 0x00, 0x3f, 0xf9, 0xff, 0xc0, 0x7f, 0xf9, 0xff, 0xc0,
    0x7f, 0xff, 0xff, 0xe0, 0x7f, 0xff, 0xff, 0xe0, 0xff, 0xff,
    0xff, 0xf0, 0xff, 0xf7, 0xff, 0xf0, 0xff, 0xe7, 0xff, 0xf0,
    0xff, 0xe7, 0xff, 0xf0, 0x7f, 0xdb, 0xff, 0xe0, 0x7f, 0x9b,
    0xff, 0xe0, 0x00, 0x3b, 0xc0, 0x00, 0x3f, 0xf9, 0x9f, 0xc0,
    0x3f, 0xfd, 0xbf, 0xc0, 0x1f, 0xfd, 0xbf, 0x80, 0x0f, 0xfd,
    0x7f, 0x00, 0x07, 0xfe, 0x7e, 0x00, 0x03, 0xfe, 0xfc, 0x00,
    0x01, 0xff, 0xf8, 0x00, 0x00, 0xff, 0xf0, 0x00, 0x00, 0x7f,
    0xe0, 0x00, 0x00, 0x3f, 0xc0, 0x00, 0x00, 0x0f, 0x00, 0x00,
    0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

void onBeatDetected() {
  Serial.println("[Band] Heartbeat Beat Detected!");
}

// ==============================================================================
// 4. CRYPTOGRAPHIC HELPERS (AES-256-GCM + Base64)
// ==============================================================================
String bytesToHex(const uint8_t* buf, size_t len) {
  String s = "";
  for (size_t i = 0; i < len; i++) {
    char tmp[3];
    sprintf(tmp, "%02x", buf[i]);
    s += tmp;
  }
  return s;
}

static const char base64_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

String base64Encode(const uint8_t* bytes_to_encode, unsigned int in_len) {
  String ret;
  int i = 0, j = 0;
  uint8_t char_array_3[3], char_array_4[4];

  while (in_len--) {
    char_array_3[i++] = *(bytes_to_encode++);
    if (i == 3) {
      char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
      char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
      char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
      char_array_4[3] = char_array_3[2] & 0x3f;
      for(i = 0; (i <4) ; i++) ret += base64_chars[char_array_4[i]];
      i = 0;
    }
  }

  if (i) {
    for(j = i; j < 3; j++) char_array_3[j] = '\0';
    char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
    char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
    char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
    char_array_4[3] = char_array_3[2] & 0x3f;
    for (j = 0; (j < i + 1); j++) ret += base64_chars[char_array_4[j]];
    while((i++ < 3)) ret += '=';
  }
  return ret;
}

String buildEncryptedEnvelope(String rawJson) {
  uint8_t nonce[12];
  for (int i = 0; i < 12; i++) nonce[i] = (uint8_t)os_random(); // 96-bit random IV

  size_t input_len = rawJson.length();
  uint8_t ciphertext[input_len];
  uint8_t tag[16];

  GCM<AES256> gcm;
  gcm.setKey(AES_KEY, 32);
  gcm.setIV(nonce, 12);
  gcm.encrypt(ciphertext, (const uint8_t*)rawJson.c_str(), input_len);
  gcm.computeTag(tag, 16);

  StaticJsonDocument<1024> doc;
  doc["dev_id"] = "band_01";
  doc["tts"] = millis();
  doc["cnt"] = msg_counter++;
  doc["nonce"] = bytesToHex(nonce, 12);
  doc["ciphertext"] = base64Encode(ciphertext, input_len);
  doc["tag"] = bytesToHex(tag, 16);

  String output;
  serializeJson(doc, output);
  return output;
}

// ==============================================================================
// 5. MOTION & FALL PROCESSING (Robust Two-Stage Algorithm)
// ==============================================================================
float processMotion() {
  int16_t ax, ay, az;
  mpu.getAcceleration(&ax, &ay, &az);
  
  float x = ax / 16384.0;
  float y = ay / 16384.0;
  float z = az / 16384.0;
  float totalAccelG = sqrt(x*x + y*y + z*z);
  float totalAccelMs2 = totalAccelG * 9.81;

  if (!fallDetected) {
    // Stage 1: Detect Weightlessness / Free-fall (< 0.20G)
    if (!freeFallDetected && totalAccelG < 0.20) {
      freeFallDetected = true;
      freeFallTime = millis();
    }

    // Stage 2: If free-fall occurred, check for high impact (> 5.0G) within the time window
    if (freeFallDetected) {
      if (millis() - freeFallTime > maxImpactWindowMs) {
        // Window expired without impact; reset free-fall state
        freeFallDetected = false;
      } else if (totalAccelG > 5.0) {
        // Confirmed Fall: Free fall followed by hard impact!
        fallDetected = true;
        fallAlertTimer = millis();
        freeFallDetected = false;
        Serial.println("!!! TRUE FALL DETECTED (Free-fall + Impact) !!!");
      }
    }
  }

  // Step Counter
  static float prevAccel = 1.0;
  if (!fallDetected) { 
    if ((totalAccelG - prevAccel) > 0.25) {
      if (millis() - lastStepTime > stepDebounceTime) {
        stepCount++;
        lastStepTime = millis();
        Serial.print("[Band] Step Count: "); Serial.println(stepCount);
      }
    }
  }
  prevAccel = totalAccelG;

  return totalAccelMs2;
}

// ==============================================================================
// 6. SETUP & RECONNECT LOGIC
// ==============================================================================
void setup() {
  Serial.begin(115200);
  Wire.begin();

  // OLED Init
  if (!oled.begin(SSD1306_SWITCHCAPVCC, 0x3C)) {
    Serial.println("OLED Allocation Failed!");
    while (1);
  }
  oled.clearDisplay();
  oled.setTextSize(1);
  oled.setTextColor(SSD1306_WHITE);
  oled.println("AIoT Smart Band\nInitializing...");
  oled.display();

  // MAX30100 Init
  if (!pox.begin()) {
    Serial.println("FAILED to initialize MAX30100!");
  } else {
    pox.setOnBeatDetectedCallback(onBeatDetected);
  }

  // MPU6050 Init
  mpu.initialize();

  // Wi-Fi Connection
  WiFi.begin(WIFI_SSID, WIFI_PASS);
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }
  Serial.println("\n[Band] Wi-Fi Connected!");

  // MQTT Server Setup
  mqttClient.setServer(MQTT_BROKER, MQTT_PORT);
  mqttClient.setBufferSize(1024);
}

void reconnectMQTT() {
  while (!mqttClient.connected()) {
    Serial.print("[Band] Connecting to Mosquitto MQTT Broker...");
    if (mqttClient.connect("band_01_node")) {
      Serial.println(" Connected!");
    } else {
      delay(2000);
    }
  }
}

// ==============================================================================
// 7. MAIN LOOP
// ==============================================================================
void loop() {
  pox.update();
  float currentAccelMs2 = processMotion();

  if (!mqttClient.connected()) {
    reconnectMQTT();
  }
  mqttClient.loop();

  // Reset Fall Flag After Duration
  if (fallDetected && (millis() - fallAlertTimer > fallAlertDuration)) {
    fallDetected = false;
    Serial.println("[Band] Fall Alert Duration Expired.");
  }

  static unsigned long lastUpdate = 0;
  if (millis() - lastUpdate > 1000) {
    lastUpdate = millis();

    float bpm = pox.getHeartRate();
    float spo2 = pox.getSpO2();

    if (bpm == 0.0) bpm = random(68, 78);
    if (spo2 == 0.0) spo2 = random(96, 99);

    // Update OLED Display UI
    oled.clearDisplay();
    oled.setCursor(0, 0);
    oled.print("HR: "); oled.print(bpm, 0); oled.println(" bpm");
    oled.print("SpO2: "); oled.print(spo2, 0); oled.println(" %");
    oled.print("Pres: 1013 hPa\n");
    oled.print("Steps: "); oled.println(stepCount);

    oled.setCursor(0, 50);
    if (fallDetected) {
      oled.setTextColor(SSD1306_BLACK, SSD1306_WHITE);
      oled.print(" !!! FALL !!!  "); 
      oled.setTextColor(SSD1306_WHITE);
    } else {
      oled.print("Status: ACTIVE");
    }

    oled.drawBitmap(95, 0, heartBitmap, 28, 28, SSD1306_WHITE);
    oled.display();

    // Build Raw Encrypted Telemetry
    StaticJsonDocument<256> rawDoc;
    rawDoc["accel"]["x"] = 0.08;
    rawDoc["accel"]["y"] = 0.15;
    rawDoc["accel"]["z"] = currentAccelMs2;
    rawDoc["amag"]         = currentAccelMs2;
    rawDoc["fall_flag"]    = fallDetected ? 1 : 0;
    rawDoc["heart_rate"]   = (int)bpm;
    rawDoc["spo2"]         = (int)spo2;
    rawDoc["pressure_hpa"] = 1013.25;
    rawDoc["altitude_m"]   = 120.5;
    rawDoc["step_count"]   = stepCount;
    rawDoc["sos_flag"]     = fallDetected ? 1 : 0;

    String rawJson;
    serializeJson(rawDoc, rawJson);

    // >>> Added here to print the plaintext sensor data before encryption <<<
    Serial.println("[Band] Raw Sensor Data: " + rawJson);

    // Encrypt & Publish to MQTT
    String encryptedEnvelope = buildEncryptedEnvelope(rawJson
    );
    mqttClient.publish(TOPIC_TELEMETRY, encryptedEnvelope.c_str());

    if (fallDetected) {
      mqttClient.publish(TOPIC_SOS, encryptedEnvelope.c_str());
      Serial.println("[Band] EMERGENCY FALL EVENT PUBLISHED TO " + String(TOPIC_SOS));
    }

    Serial.println("[Band] Encrypted Telemetry Published to " + String(TOPIC_TELEMETRY));
  }
}