# MQTT_Framework

This software is part of the Thesis Project for the **Bachelor in Computer Science at the Free University of Bolzano**. The
idea was to develop a software, a framework with different tools that could automatize the security testing process for
developers, in order to save time and help them find the most common vulnerabilities and bad implementation practices of MQTT protocol in IoT environments. This software has to adapt to different scenarios and implementations of the protocol and for this reason the tool should be highly customisable.

## What is MQTT

MQTT is a protocol for information broadcasting between IoT devices originally designed by Andy Stanford-Clark and Arlen Nippe, the latest version is 5.0 although many devices still use version 3. It complies with the Open Artwork System Interchange Standard (OASIS) and is developed as an extremely lightweight transport model, aiming to have a very low code base and minimal bandwidth usage. These features are ideal for devices with limited resources that need a _publish/subscribe_ communication pattern, which provides one-to-many message distribution. As already mentioned, it has become a standard in the smart device industry also for its flexibility in being deployed with different network
technologies, becoming vital for fields such as automotive, industrial manufacturing, telecommunications, etc.

## Requirements
In order to run the framework you need the libraries you find in _requirements.txt_ and Radamasa software. To install it
please refer to the [official repo](https://gitlab.com/akihe/radamsa). 

The framework has been tested on Windows 10 and GNU/Linux operating systems, both on Raspberry Pi and an average performance PC. 

### The plugins

The software comes with 5 plugins with basic functionalities: Network scanner, Network sniffer, Credentials cracker,
Topics listener and Payload injector.

The framework supports Shodan.io analysis, to enable it just add your API KEY in `./utils/constants.py`.

### Adding a custom module

Each module must have its own ArgumentParser instance, which is a class that handles user input together with python's cli. When a new module is created, it has to respect the following criteria:
- **Inheritance:** A new Mixin class must be produced in order to plug the custom module to the framework. This class has
to inherit InterfaceMixin and must create a new, unique, instance of ArgumentParser. With this object the developer can
add/handle custom arguments needed by its module with some help text.
-  **The do\_ operator:** Then the function `do\_"name of the command" `must be defined with the decorators
`@with\_category` and `@with\_argparser`. In this way the framework will know what code to execute for a specific
command, what category it is related to and which argument parser apply when the module is loaded with the framework
cli. They are also used to check whether a `-help` option is specified.
- **Exporting the module:** The custom code has to be exported from the mixins package first, by importing it in
`mixins\_init_.py`. Then the module has to be added to the mixins array in the _MQTTcli_ class.

