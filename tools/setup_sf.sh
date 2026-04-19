#!/bin/bash

sudo /opt/mellanox/iproute2/sbin/mlxdevm port add pci/0000:03:00.0 flavour pcisf pfnum 0 sfnum 4
sudo /opt/mellanox/iproute2/sbin/mlxdevm port add pci/0000:03:00.0 flavour pcisf pfnum 0 sfnum 5

sudo /opt/mellanox/iproute2/sbin/mlxdevm port show

sudo /opt/mellanox/iproute2/sbin/mlxdevm port function set pci/0000:03:00.0/229613 hw_addr 02:25:f2:8d:a2:4c trust on state active
sudo /opt/mellanox/iproute2/sbin/mlxdevm port function set pci/0000:03:00.0/229614 hw_addr 02:25:f2:8d:a2:5c trust on state active
