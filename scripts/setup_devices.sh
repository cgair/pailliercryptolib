# Copyright (C) 2022-2023 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

#!/bin/bash

# Refresh
echo "sudo service restart qat_service"
#sudo service qat_service restart
sudo systemctl restart qat_service.service

num_phys_dev=$(lspci -d 8086:4940 | wc -l) 
if [ $num_phys_dev -eq 0 ]; then
  echo "No QAT Device Found !"
  exit
else
  echo "$num_phys_dev QAT Devices Found !"	
fi

total_virt_func=$(lspci -d 8086:4941 | wc -l) 
num_virt_func=`expr $total_virt_func / $num_phys_dev`
dev_step=1

if [ $# -eq 0 ]; then
  echo "Usage: ./setup_devices <num_phys_dev> <num_virt_inst> <conf_virt_inst>"
  echo "   Parameters:"
  echo "   -- num_phys_dev:   Number of physical devices to be active. (default: auto)"
  echo "   -- conf_virt_func: Number of configured virtual functions per device. (default: 0)"
  echo "   -- num_virt_func:  Number of virtual functions to be active per device. (default: 0)"
fi

nphysdev=$num_phys_dev
if [ -n "$1" ]; then
  nphysdev=$1
  if [ $nphysdev -gt $num_phys_dev ]; then
    nphysdev=$num_phys_dev
  fi
fi

conf_virt_func=0
# Check if virtual function is enabled
if [ $num_virt_func -gt 0 ]; then
  conf_virt_func=1
fi 

if [ -n "$2" ]; then
  conf_virt_func=$2
  # if user attempts to request higher than available
  if [ $conf_virt_func -gt $num_virt_func ]; then
    conf_virt_func=$num_virt_func
  fi
fi

# Shutdown QAT PFs
i=0
while [ $i -lt $num_phys_dev ]; 
do 
  echo "sudo adf_ctl qat_dev$i down"; 
  sudo adf_ctl qat_dev$i down; 
  i=`expr $i + 1`; 
done

# Reconfigure Target QAT PFs
i=0
n=$nphysdev
while [ $i -lt $n ]; 
do 
  echo "sudo cp config/4xxx_dev0.conf /etc/4xxx_dev$i.conf"; 
  sudo cp config/4xxx_dev0.conf /etc/4xxx_dev$i.conf; 
  echo "sudo adf_ctl qat_dev$i up"; 
  sudo adf_ctl qat_dev$i up; 
  i=`expr $i + 1`; 
done

# Refresh
echo "sudo service restart qat_service"
#sudo service qat_service restart
sudo systemctl restart qat_service.service

# If Virtualization Mode Enabled
start=0
if [ $num_virt_func -gt 0 ]; then 
  if [ $conf_virt_func -gt 0 ]; then 
    start=$num_phys_dev
    dev_step=$num_virt_func
  fi
fi

# Shutdown QAT VFs
i=$start
stop=`expr $num_phys_dev \\* $num_virt_func`
stop=`expr $start + $stop`
step=$dev_step
while [ $i -lt $stop ]; 
do 
  echo "sudo adf_ctl qat_dev$i down"; 
  sudo adf_ctl qat_dev$i down; 
  i=`expr $i + 1`; 
done

#i=0
#while [ $i -lt $total_virt_func ]; 
#do 
#  echo "sudo cp config/4xxxvf_dev0.conf /etc/4xxxvf_dev$i.conf"; 
#  sudo cp config/4xxxvf_dev0.conf /etc/4xxxvf_dev$i.conf; 
#  i=`expr $i + 1`; 
#done

i=0
while [ $i -lt $nphysdev ]; 
do 
  # Reconfigure QAT PF
  echo "sudo cp config/4xxx_dev0.conf /etc/4xxx_dev$i.conf"; 
  sudo cp config/4xxx_dev0.conf /etc/4xxx_dev$i.conf; 
  # Start QAT PF
  echo "sudo adf_ctl qat_dev$i up"; 
  sudo adf_ctl qat_dev$i up; 
  i=`expr $i + 1`; 
done

start=$num_phys_dev
i=$start
stop=`expr $nphysdev \\* $num_virt_func`
stop=`expr $start + $stop`
step=$dev_step
while [ $i -lt $stop ];
do
  k=`expr $i - $start`
  # Reconfigure QAT VF (must match PF's config)
  echo "sudo cp config/4xxxvf_dev0.conf /etc/4xxxvf_dev$k.conf"; 
  sudo cp config/4xxxvf_dev0.conf /etc/4xxxvf_dev$k.conf; 
  # Start QAT VF
  echo "adf_ctl qat_dev$i up"
  sudo adf_ctl qat_dev$i up;
  # Start up additional instances mapped to the same physical device
  j=1;
  while [ $j -lt $conf_virt_func ]; 
  do
    dev_id=`expr $i + $j`;
    k=`expr $dev_id - $start`;
    # Reconfigure QAT VF (must match PF's config)
    echo "sudo cp config/4xxxvf_dev0.conf /etc/4xxxvf_dev$k.conf"; 
    sudo cp config/4xxxvf_dev0.conf /etc/4xxxvf_dev$k.conf; 
    # Start QAT VF
    echo "adf_ctl qat_dev$dev_id up"
    sudo adf_ctl qat_dev$dev_id up;
    j=`expr $j + 1`;
  done
  i=`expr $i + $dev_step`
done

# Shutdown Unused QAT PFs
i=$nphysdev
while [ $i -lt $num_phys_dev ]; 
do 
  echo "sudo adf_ctl qat_dev$i down"; 
  sudo adf_ctl qat_dev$i down; 
  i=`expr $i + 1`; 
done
