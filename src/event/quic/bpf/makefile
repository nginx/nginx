CFLAGS=-O2 -Wall

LICENSE=BSD

PROGNAME=ngx_quic_reuseport_helper
RESULT=ngx_event_quic_bpf_code
DEST=../$(RESULT).c

all: $(RESULT)

$(RESULT): $(PROGNAME).o
	LICENSE=$(LICENSE) PROGNAME=$(PROGNAME) bash ./bpfgen.sh $< > $@

DEFS=-DPROGNAME=\"$(PROGNAME)\"                                               \
     -DLICENSE_$(LICENSE)                                                     \
     -DLICENSE=\"$(LICENSE)\"                                                 \

$(PROGNAME).o: $(PROGNAME).c
	clang $(CFLAGS) $(DEFS) -target bpf -c $< -o $@

install: $(RESULT)
	cp $(RESULT) $(DEST)

clean:
	@rm -f $(RESULT) *.o

debug: $(PROGNAME).o
	llvm-objdump -S --no-show-raw-insn $<

.DELETE_ON_ERROR:
