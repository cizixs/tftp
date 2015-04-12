import socket

MAXSIZE = 500
PORT = 69

def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("", PORT))
    print "listening on {}".format(PORT)

    while True:
    	data, addr = s.recvfrom(MAXSIZE)
    	print "{} from {}".format(data, addr)
    	s.sendto("Hello, {}".format(addr), addr)


if __name__ == "__main__":
	main()
