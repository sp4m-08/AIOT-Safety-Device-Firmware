#include <ESP8266WiFi.h>
#include <PubSubClient.h>
#include <ArduinoJson.h>
#include <Wire.h>
#include <MPU6050.h>
#include <Crypto.h>
#include <AES.h>
#include <GCM.h>

// ==============================================================================
// 1. HARDWARE PIN DEFINITIONS (ESP8266 NodeMCU Pins)
// ==============================================================================
#define TRIG_PIN D5   // GPIO14 - Sonar Trigger
#define ECHO_PIN D6   // GPIO12 - Sonar Echo
#define BUZZER_PIN D7 // GPIO13 - Active Buzzer Alert

// Note: MPU6050 I2C SDA = D2 (GPIO4), SCL = D1 (GPIO5) by default

// ==============================================================================
// 2. NETWORK & MQTT BROKER CONFIGURATION
// ==============================================================================
const char* WIFI_SSID   = "TESTESP";               // Your Wi-Fi Name
const char* WIFI_PASS   = "12345678";            // Your Wi-Fi Password
const char* MQTT_BROKER = "10.196.169.114";        // Your Laptop's Wi-Fi IP Address
const int   MQTT_PORT   = 1883;                  // Local Mosquitto Port
const char* MQTT_TOPIC  = "aiot/v1/cane/telemetry";

// Master 256-bit Secret Key (Matches server/src/crypto/aesGcmEngine.ts)
const uint8_t AES_KEY[32] = {
  0xa1,0xb2,0xc3,0xd4,0xe5,0xf6,0x07,0x18,
  0x29,0x3a,0x4b,0x5c,0x6d,0x7e,0x8f,0x90,
  0x12,0x34,0x56,0x78,0x90,0xab,0xcd,0xef,
  0x12,0x34,0x56,0x78,0x90,0xab,0xcd,0xef
};

WiFiClient espClient;
PubSubClient mqttClient(espClient);
MPU6050 mpu;

uint32_t msg_counter = 1;

// ----- Fall Detection Logic -----
#define FREE_FALL_THRESHOLD  0.4
#define IMPACT_THRESHOLD     2.5

bool fallDetected = false;
unsigned long fallAlertTimer = 0;
const unsigned long fallAlertDuration = 3000;

// ==============================================================================
// 3. CRYPTOGRAPHIC HELPERS (AES-256-GCM + Base64)
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
      for(i = 0; (i < 4) ; i++) ret += base64_chars[char_array_4[i]];
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
  doc["dev_id"] = "cane_01";
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
// 4. SENSOR READERS
// ==============================================================================
float readDistanceMeters() {
  digitalWrite(TRIG_PIN, LOW);
  delayMicroseconds(2);
  digitalWrite(TRIG_PIN, HIGH);
  delayMicroseconds(10);
  digitalWrite(TRIG_PIN, LOW);

  long duration = pulseIn(ECHO_PIN, HIGH, 30000); // 30ms timeout (~5m max range)
  if (duration == 0) return 2.0;

  float distance_cm = duration * 0.0343 / 2.0;
  return distance_cm / 100.0; // Convert to meters
}

float processCaneMotion(float &ax_out, float &ay_out, float &az_out) {
  int16_t ax, ay, az;
  mpu.getAcceleration(&ax, &ay, &az);

  float x = ax / 16384.0;
  float y = ay / 16384.0;
  float z = az / 16384.0;
  
  ax_out = x * 9.81;
  ay_out = y * 9.81;
  az_out = z * 9.81;

  float totalAccelG = sqrt(x*x + y*y + z*z);

  // Check for candidate fall (Impact > 2.5g or Freefall < 0.4g)
  if (!fallDetected) {
    if (totalAccelG > IMPACT_THRESHOLD || totalAccelG < FREE_FALL_THRESHOLD) {
      fallDetected = true;
      fallAlertTimer = millis();
      Serial.println("[Cane] !!! CANDIDATE FALL IMPACT DETECTED !!!");
    }
  }

  return totalAccelG * 9.81; // Acceleration in m/s^2
}

// ==============================================================================
// 5. SETUP & RECONNECT LOGIC
// ==============================================================================
void setup() {
  Serial.begin(115200);

  // Initialize Pins
  pinMode(TRIG_PIN, OUTPUT);
  pinMode(ECHO_PIN, INPUT);
  pinMode(BUZZER_PIN, OUTPUT);
  digitalWrite(TRIG_PIN, LOW);
  digitalWrite(BUZZER_PIN, LOW);

  // Initialize Wire & MPU6050
  Wire.begin();
  mpu.initialize();
  if (mpu.testConnection()) {
    Serial.println("[Cane] MPU6050 Connected!");
  } else {
    Serial.println("[Cane] MPU6050 Connection FAILED!");
  }

  // Connect to Wi-Fi
  Serial.print("[Cane] Connecting to Wi-Fi: ");
  Serial.println(WIFI_SSID);
  WiFi.begin(WIFI_SSID, WIFI_PASS);
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }
  Serial.println("\n[Cane] Wi-Fi Connected!");

  // Setup MQTT Client & EXPAND BUFFER SIZE TO 1024
  mqttClient.setServer(MQTT_BROKER, MQTT_PORT);
  mqttClient.setBufferSize(1024); // Critical fix for encrypted envelope size
}

void reconnectMQTT() {
  while (!mqttClient.connected()) {
    Serial.print("[Cane] Connecting to Mosquitto MQTT Broker at ");
    Serial.print(MQTT_BROKER);
    Serial.print("...");
    if (mqttClient.connect("cane_01_node")) {
      Serial.println(" Connected!");
    } else {
      Serial.print(" Failed (rc=");
      Serial.print(mqttClient.state());
      Serial.println("). Retrying in 2 seconds...");
      delay(2000);
    }
  }
}

// ==============================================================================
// 6. MAIN LOOP
// ==============================================================================
void loop() {
  if (!mqttClient.connected()) {
    reconnectMQTT();
  }
  mqttClient.loop();

  // Reset fall flag after alert duration
  if (fallDetected && (millis() - fallAlertTimer > fallAlertDuration)) {
    fallDetected = false;
    Serial.println("[Cane] Candidate Fall Window Expired.");
  }

  static unsigned long lastUpdate = 0;
  if (millis() - lastUpdate > 500) { // 2 Hz Telemetry Loop
    lastUpdate = millis();

    // Read Hardware Sensors
    float distance_m = readDistanceMeters();
    float ax, ay, az;
    float amag = processCaneMotion(ax, ay, az);

    // Buzzer Proximity Warning (< 0.80 meters)
    bool buzzer_active = (distance_m < 0.80);
    digitalWrite(BUZZER_PIN, buzzer_active ? HIGH : LOW);

    // Build Raw Telemetry JSON
    StaticJsonDocument<256> rawDoc;
    rawDoc["distance_m"]    = distance_m;
    rawDoc["buzzer_active"] = buzzer_active;
    rawDoc["accel"]["x"]    = ax;
    rawDoc["accel"]["y"]    = ay;
    rawDoc["accel"]["z"]    = az;
    rawDoc["amag"]          = amag;
    rawDoc["fall_flag"]     = fallDetected ? 1 : 0;
    rawDoc["heart_rate"]    = 74; // Handle pulse oximeter
    rawDoc["spo2"]          = 98;

    String rawJson;
    serializeJson(rawDoc, rawJson);

    // Encrypt into AES-256-GCM Envelope & Publish over MQTT
    String encryptedEnvelope = buildEncryptedEnvelope(rawJson);
    bool published = mqttClient.publish(MQTT_TOPIC, encryptedEnvelope.c_str());

    if (published) {
      Serial.print("[Cane] Distance: "); Serial.print(distance_m); Serial.print("m | ");
      Serial.print("a_mag: "); Serial.print(amag); Serial.print("m/s² | ");
      Serial.println("-> Encrypted Telemetry Published!");
    } else {
      Serial.println("[Cane] Failed to publish MQTT message.");
    }
  }
}