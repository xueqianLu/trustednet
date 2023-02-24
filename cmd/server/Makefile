DEST=${PWD}
BIN=trustedserver

.PHONY: all bin deps clean sim run host

all: bin

bin:
	ego-go build -o=${BIN}
	ego sign ${BIN}

sim:
	OE_SIMULATION=1 ego run ${BIN}

run:
	ego run ${BIN}

clean:
	@rm -f $(BIN)
