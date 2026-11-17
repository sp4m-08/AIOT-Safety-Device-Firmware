#include <WiFi.h>
#include <PubSubClient.h>
#include <ArduinoJson.h>
#include <Wire.h>
#include <Adafruit_MPU6050.h>
#include <Adafruit_Sensor.h>
#include "mbedtls/gcm.h"
#include "mbedtls/base64.h"

// ==============================================================================
// 1. HARDWARE PIN DEFINITIONS (Your Exact Setup)
// ==============================================================================
#define SDA_PIN  21
#define SCL_PIN  22
#define TRIG_PIN 5
#define ECHO_PIN 18

// ==============================================================================
// 2. NETWORK & BROKER CONFIGURATION
// ==============================================================================
const char* WIFI_SSID   = "TESTESP";       // Your Wi-Fi Name

const char* WIFI_PASS   = "12345678";   // Your Wi-Fi Password

const char* MQTT_BROKER = "10.196.169.114";      // Your Laptop's Wi-Fi IP Address
const int   MQTT_PORT   = 1883;                   // Local Mosquitto Port
const char* MQTT_TOPIC  = "aiot/v1/specs/telemetry";

// Master 256-bit Secret Key (Matches server/src/crypto/aesGcmEngine.ts)
const uint8_t AES_KEY[32] = {
  0xa1,0xb2,0xc3,0xd4,0xe5,0xf6,0x07,0x18,
  0x29,0x3a,0x4b,0x5c,0x6d,0x7e,0x8f,0x90,
  0x12,0x34,0x56,0x78,0x90,0xab,0xcd,0xef,
  0x12,0x34,0x56,0x78,0x90,0xab,0xcd,0xef
};

// ==============================================================================
// 3. GLOBAL INSTANCES & STATE
// ==============================================================================
Adafruit_MPU6050 mpu;
WiFiClient espClient;
PubSubClient mqttClient(espClient);

uint32_t msg_counter = 1;
float current_yaw = 0.0;
unsigned long last_time = 0;

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

String base64Encode(const uint8_t* input, size_t input_len) {
  size_t olen = 0;
  mbedtls_base64_encode(NULL, 0, &olen, input, input_len);
  uint8_t output[olen + 1];
  mbedtls_base64_encode(output, olen, &olen, input, input_len);
  output[olen] = '\0';
  return String((char*)output);
}

String buildEncryptedEnvelope(String rawJson) {
  uint8_t nonce[12];
  for (int i = 0; i < 12; i++) nonce[i] = (uint8_t)esp_random(); // 96-bit random IV

  size_t input_len = rawJson.length();
  uint8_t ciphertext[input_len];
  uint8_t tag[16];

  mbedtls_gcm_context gcm;
  mbedtls_gcm_init(&gcm);
  mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, AES_KEY, 256);
  mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, input_len, nonce, 12, NULL, 0,
                            (const uint8_t*)rawJson.c_str(), ciphertext, 16, tag);
  mbedtls_gcm_free(&gcm);

  // Format Envelope JSON
  StaticJsonDocument<1024> doc;
  doc["dev_id"] = "specs_01";
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
// 5. SENSOR READERS
// ==============================================================================
float readDistanceMeters() {
  digitalWrite(TRIG_PIN, LOW);
  delayMicroseconds(2);
  digitalWrite(TRIG_PIN, HIGH);
  delayMicroseconds(10);
  digitalWrite(TRIG_PIN, LOW);

  long duration = pulseIn(ECHO_PIN, HIGH, 30000); // 30ms timeout (~5m max range)
  if (duration == 0) return 2.0; // Default max distance if out of range

  float distance_cm = duration * 0.0343 / 2.0;
  return distance_cm / 100.0; // Convert cm to meters
}

// ==============================================================================
// 6. SETUP & RECONNECT LOGIC
// ==============================================================================
void setup() {
  Serial.begin(115200);

  // Initialize Ultrasonic Pins
  pinMode(TRIG_PIN, OUTPUT);
  pinMode(ECHO_PIN, INPUT);
  digitalWrite(TRIG_PIN, LOW);

  // Initialize I2C and MPU6050
  Wire.begin(SDA_PIN, SCL_PIN);
  if (!mpu.begin()) {
    Serial.println("ERROR: MPU6050 not detected! Check wiring.");
    while (1) { delay(1000); }
  }

  mpu.setAccelerometerRange(MPU6050_RANGE_8_G);
  mpu.setGyroRange(MPU6050_RANGE_500_DEG);
  mpu.setFilterBandwidth(MPU6050_BAND_21_HZ);
  Serial.println("MPU6050 & Sonar Initialized Successfully.");

  // Connect to Wi-Fi
  Serial.print("Connecting to Wi-Fi: ");
  Serial.println(WIFI_SSID);
  WiFi.begin(WIFI_SSID, WIFI_PASS);
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }
  Serial.println("\nWi-Fi Connected!");

  // Configure MQTT Server & Expand Buffer to 1024 Bytes
  mqttClient.setServer(MQTT_BROKER, MQTT_PORT);
  mqttClient.setBufferSize(1024); // <-- CRITICAL FIX FOR ENCRYPTED PAYLOADS!
  
  last_time = millis();
}

void reconnectMQTT() {
  while (!mqttClient.connected()) {
    Serial.print("Connecting to Mosquitto MQTT Broker at ");
    Serial.print(MQTT_BROKER);
    Serial.print("...");
    
    if (mqttClient.connect("specs_01_node")) {  
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
// 7. MAIN LOOP
// ==============================================================================
void loop() {
  if (!mqttClient.connected()) {
    reconnectMQTT();
  }
  mqttClient.loop();

  // Read Sensors
  sensors_event_t accel, gyro, temp;
  mpu.getEvent(&accel, &gyro, &temp);
  float distance_m = readDistanceMeters();

  // Calculate Pitch (from Accelerometer)
  float pitch_deg = atan2(-accel.acceleration.x, sqrt(accel.acceleration.y * accel.acceleration.y + accel.acceleration.z * accel.acceleration.z)) * 180.0 / M_PI;

  // Integrate Gyro Z for Yaw angle
  unsigned long now = millis();
  float dt = (now - last_time) / 1000.0;
  last_time = now;
  current_yaw += gyro.gyro.z * (180.0 / M_PI) * dt;

  // Print to Serial Monitor
  Serial.print("Distance: "); Serial.print(distance_m); Serial.print(" m | ");
  Serial.print("Pitch: "); Serial.print(pitch_deg); Serial.print("° | ");
  Serial.print("Yaw: "); Serial.print(current_yaw); Serial.println("°");

  // Create Raw Telemetry JSON
  StaticJsonDocument<256> rawDoc;
  rawDoc["distance_m"]  = distance_m;
  rawDoc["pitch_deg"]   = pitch_deg;
  rawDoc["yaw_deg"]     = current_yaw;
  rawDoc["battery_pct"] = 92;

  String rawJson;
  serializeJson(rawDoc, rawJson);  

  // Encrypt JSON payload into AES-256-GCM Envelope
  String encryptedEnvelope = buildEncryptedEnvelope(rawJson);

  // Publish to MQTT Topic
  bool published = mqttClient.publish(MQTT_TOPIC, encryptedEnvelope.c_str());
  if (published) {
    Serial.println("-> Encrypted Telemetry Published to " + String(MQTT_TOPIC));
  } else {
    Serial.println("-> Failed to Publish MQTT Message.");
  }

  delay(500); // Send telemetry every 500ms (2 Hz)
}