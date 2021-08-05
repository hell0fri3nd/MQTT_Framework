# MQTT_Framework

This software is part of the **Thesis Project** for the **Bachelor in Computer Science at the Free University of Bolzano**. The idea was to develop a software, a framework with different tools that could automatize the security testing process for developers, in order to save time and help them find the most common vulnerabilities and bad implementation practices of MQTT protocol in IoT environments. This software has to adapt to different scenarios and implementations of the protocol and for this reason the tool should be highly customisable.

<img src="https://www.eitfood.eu/media/partners-startups/University_of_Bolzano.png" style="zoom: 25%;" />

## What is MQTT

MQTT is a protocol for information broadcasting between IoT devices originally designed by Andy Stanford-Clark and Arlen Nippe, the latest version is 5.0 although many devices still use version 3. It complies with the Open Artwork System Interchange Standard (OASIS) and is developed as an extremely lightweight transport model, aiming to have a very low code base and minimal bandwidth usage. These features are ideal for devices with limited resources that need a _publish/subscribe_ communication pattern, which provides one-to-many message distribution. As already mentioned, it has become a standard in the smart device industry also for its flexibility in being deployed with different network
technologies, becoming vital for fields such as automotive, industrial manufacturing, telecommunications, etc.

<img src="https://mqtt.org/assets/img/mqtt-logo.svg" style="zoom:50%;" />

## 📌 Requirements
In order to run the framework you need to install the following package:

- <u>**Docker:**</u> To deploy the framework it is easier with Docker containers, you can download Docker [here](https://www.docker.com/products/docker-desktop). 

Thanks to Docker you can install all the libraries with one command while drinking a cup of coffee, containers make our life easier! The framework has been tested on Windows 10 and Debian-based operating systems, both on Raspberry Pi and an average performance Windows machine. 

#### ⚠️ ALTERNATIVE - If Docker raises issues ⚠️

In case Docker raises issues with the deployment, the framework can be installed manually. To do this, please refer to `requirements.txt` and the following list of libraries:

- <u>Nmap:</u>  Please refer to [Nmap website](https://nmap.org/download.html) to install the correct version for your environment. 
- <u>Tshark:</u> Follow [Tshark docs](https://tshark.dev/setup/install/#installing-tshark-only) and learn how to install the right version for you. The framework needs Tshark only, but with Wireshark installation you get both Tshark and its GUI.
- <u>Radamsa:</u> Check out the [official repo](https://gitlab.com/akihe/radamsa) to compile and deploy the library in your machine. 
- <u>Prettytable</u>: You can find the library [here](https://pypi.org/project/prettytable/). If you are running the framework in a Debian-based environment, remember to install *less* with the following command `apt update && apt install less`

Alternatively, you can set up a virtual environment, however the dependencies listed above shall be installed manually in any case.

## 📌 Installation

The framework can be installed through **Docker**. 

- pull the repo 
- move inside the framework's main directory with `cd MQTT_Framework`  
- run `docker build .` to create the Docker image
- check if the image has no name with `docker images` (pip might have issues with *python-nmap* package, but don't worry it works anyway), solve the issue with `docker tag <IMAGE_ID> <image-name>`
- run the image by typing `sudo docker run -it <image-name>` 

## 📌 Basic functionalities

### The plugins

The software comes with 5 plugins with basic functionalities: Network scanner, Network sniffer, Credentials cracker,
Topics listener and Payload injector.

The framework supports Shodan.io analysis, to enable it just add your API KEY in `./utils/constants.py`. If the file is not present, please create a new one.

### Adding a custom module

Each module must have its own ArgumentParser instance, which is a class that handles user input together with python's cli. When a new module is created, it has to respect the following criteria:
- **Inheritance:** A new Mixin class must be produced in order to plug the custom module to the framework. This class has to inherit InterfaceMixin and must create a new, unique, instance of ArgumentParser. With this object the developer can add/handle custom arguments needed by its module with some help text.
- **The do_ operator:** Then the function `do_<name of the command> `must be defined with the decorators `@with_category` and `@with_argparser`. In this way the framework will know what code to execute for a specific
  command, what category it is related to and which argument parser apply when the module is loaded with the framework cli. They are also used to check whether a `-help` option is specified.
- **Exporting the module:** The custom code has to be exported from the mixins package first, by importing it in
  `mixins_init_.py`. Then the module has to be added to the mixins array in the _MQTTcli_ class.

## 📌 Testing in a real life environment

It is possible to set up a safe environment with software used in real life scenarios. The framework has been tested in order to prove naïve/unsafe implementations of MQTT brokers with a software for home IoT devices management and an android application were configured to work with a Mosquitto broker. The management software of use is [Home Assistant](www.home-assistant.io), which is an open source home automation software for DIY enthusiasts. It is a lightweight server developed specifically for programmable-boards deployment, it supports over 1000 devices including Alexa and Google Home, and can be extended with multiple add-ons; this flexibility allows MQTT configuration with the Mosquitto broker. The idea is to simulate a smart alarm system which then could be controlled with the Home Assistant platform and the [Alarm Panel](https://play.google.com/store/apps/details?id=com.thanksmister.iot.mqtt.alarmpanel&hl=it&gl=US) android application.

- Refer to [Mosquitto website](https://mosquitto.org/) to install and deploy Mosquitto with Docker.

- Deploy Home Assistant container following this [guide](https://www.home-assistant.io/installation/raspberrypi#install-home-assistant-container).

- Open "*Manual configuration steps*" tab at this [page](https://www.home-assistant.io/integrations/mqtt) to link the software with your Mosquitto broker.

- To create a custom alarm panel in your installation, add the following to your `configuration.yaml` file: 

  ```yaml
  alarm_control_panel:
    - platform: manual_mqtt
      state_topic: home/alarm
      command_topic: home/alarm/set
      pending_time: 60
      trigger_time: 1800
      disarm_after_trigger: false
      delay_time: 30
      armed_home:
        pending_time: 0
        delay_time: 0
      armed_away:
        pending_time: 60
        delay_time: 30
  ```

- **(Optional)** If you have one, add any sensors (for example Zwave door sensors/sirens) and configure automations to trigger the alarm in Home Assistant.

- On the android application, under the settings insert the MQTT information (IP, ports, credentials, etc.) that you configured in Home Assistant for your MQTT service.

Now you are ready to make some tests.

## 📌 References

A special thanks to <u>**Akamai Threat Research**</u> and <u>**Agneta Akorevaar (Kiwi PyCon 2019)**</u> for the useful resources.
