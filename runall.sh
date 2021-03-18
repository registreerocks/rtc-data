#!/bin/sh -e

make
cd bin/
./rtc_data_service
