# The AES key is read from the environment: it used to sit here in clear text,
# which made the encryption of the node credentials pointless for anyone
# with access to the repository.
#
#   export H2S_AES_KEY='<32 bytes key>'
#   make
#
# It must stay the same key the files under ./nodes were encrypted with.
key ?= $(H2S_AES_KEY)

h2s:
	@if [ -z "$(key)" ]; then \
		echo "H2S_AES_KEY is not set. Run: export H2S_AES_KEY='<32 bytes key>'"; \
		exit 1; \
	fi
	go build -o h2s -ldflags='-X main.AesKeyString=$(key)'
clean:
	rm h2s
