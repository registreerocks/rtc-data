.PHONY: data_system

data_system:
	make -f datasystem.mk

.PHONY: clean
clean:
	make -f datasystem.mk clean
