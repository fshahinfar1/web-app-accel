SOURCE = web_server_accel.c
BINARY = server

CC = gcc
CFLAGS = -g -O2 -Wall

CURDIR=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
YAML=$(CURDIR)/build_config.yaml

include ../common/common.mk
