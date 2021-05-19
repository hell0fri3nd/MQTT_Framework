import paho.mqtt.client as mqtt


# Define on_connect event Handler
def on_connect(mosq, obj, rc, mqtt_client, topic):
    # Subscribe to a the Topic
    mqtt_client.subscribe(topic, 0)


# Define on_subscribe event Handler
def on_subscribe(mosq, obj, mid, granted_qos):
    print("Subscribed to MQTT Topic")


# Define on_message event Handler
def on_message(mosq, obj, msg):
    print(msg.payload)


def send_message(host, port, topic_name, message):
    # Define Variables
    MQTT_HOST = host
    MQTT_PORT = port
    MQTT_KEEPALIVE_INTERVAL = 5
    MQTT_TOPIC = topic_name
    MQTT_MSG = message

    # Initiate MQTT Client
    mqttc = mqtt.Client()

    # Register Event Handlers
    mqttc.on_message = on_message
    mqttc.on_connect = on_connect
    mqttc.on_subscribe = on_subscribe

    # Connect with MQTT Broker
    mqttc.connect(MQTT_HOST, MQTT_PORT, MQTT_KEEPALIVE_INTERVAL)

    # Continue the network loop
    mqttc.loop_forever()
