#!/bin/bash

tap_interface_name="tap0"
action="${1}"

if [ "${action}" == "deinit" ]; then
    ip link set dev "${tap_interface_name}" down
    ip tuntap del mode tap dev "${tap_interface_name}"

    echo "${tap_interface_name} interface is deleted"
else
    tap_created=$(ip tuntap | awk '{print $1}')
    if [ "${tap_created}" != "${tap_interface_name}:" ]; then
        ip tuntap add mode tap dev "${tap_interface_name}"
        ip addr add 10.0.3.0/24 dev "${tap_interface_name}"
        ip link set dev "${tap_interface_name}" up

        echo "${tap_interface_name} interface is added, up and has associated ip address"
    else
        echo "${tap_interface_name} interface is added already"
    fi
fi
