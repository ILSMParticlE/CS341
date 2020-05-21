/*
 * E_TCPAssignment.hpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: Keunhong Lee
 */

#ifndef E_TCPASSIGNMENT_HPP_
#define E_TCPASSIGNMENT_HPP_


#include <E/Networking/E_Networking.hpp>
#include <E/Networking/E_Host.hpp>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/in.h>


#include <E/E_TimerModule.hpp>

#include <E/E_TimeUtil.hpp>

namespace E
{

class TCPAssignment : public HostModule, public NetworkModule, public SystemCallInterface, private NetworkLog, private TimerModule
{
private:
	enum SocketState{
		S_CLOSED,
		S_LISTEN,
		S_SYN_SENT,
		S_SYN_RCVD,
		S_SYN_SIMRCVD,
		S_ESTAB,

		S_FIN_WAIT_1,
		S_FIN_WAIT_2,
		S_TIMED_WAIT,
		S_CLOSE_WAIT,
		S_CLOSING,		// simulaneous close

		S_LAST_ACK
	};

	/* packet header flags */
	const int FIN = 1 << 0;
	const int SYN = 1 << 1;
	const int RST = 1 << 2;
	const int PSH = 1 << 3;
	const int ACK = 1 << 4;
	const int URG = 1 << 5;
	/* packet header flags end */

	class Socket;

	class TimerPayload{
    public:
		Socket *sock;
		uint32_t seq;
		UUID tUUID;

		bool retransmit;
		Time sent;
		Time timeout;

		TimerPayload(bool isRetransmit);
		~TimerPayload();
	};

	class ListenQueue{
	public:
		std::queue<Socket *> pending;
		std::queue<int> pending_fd;
		
		size_t cur_backlog;
		size_t backlog;

		ListenQueue(size_t backlog);
		~ListenQueue();
	};

	class Socket{
	public:
		struct sockaddr src;	// in host byte order
		struct sockaddr dest;

		bool bound;

		SocketState state;
		uint32_t seq_send;		// seq num
		uint32_t seq_recv;		// ack num

		// window related members
		uint16_t max_wnd = 51200;
		uint16_t rwnd;		// my window size
		uint16_t swnd;			// window size of other side

		// buffer related members
		void *rbuf;
		size_t buf_size;
		size_t in_flight;
		std::unordered_map<uint32_t, size_t> seqn_to_len;		// temporary member in 3-1

		std::vector<uint32_t> unacked;
		std::unordered_map<uint32_t, Packet *> acktop;
		int dup_ack;
		uint16_t last_ack_flags;
		uint32_t last_ack;
		bool close_sim = false;

		std::unordered_map<uint32_t, TimerPayload *> timerlist;

		ListenQueue *lq;

		Socket();
		~Socket();
		size_t readBuf(const void *buf, size_t count);

	};
	class PCB{
	public:
		std::unordered_map<int, Socket *> fdlist;

		bool block = false;
		struct blockedInfo{
			SystemCall syscall;
			UUID syscallUUID;
			
			int sockfd;
			struct sockaddr *addr;
			socklen_t addr_len;
			socklen_t *addr_len_ptr;

			const void *buf;
			size_t count;

			int ret;
		};
		struct blockedInfo *blocked_info = nullptr;

		void block_syscall(SystemCall syscall, UUID syscallUUID, int sockfd,
						struct sockaddr *addr, socklen_t addrlen, socklen_t *addr_len_ptr,
						const void *buf, size_t count,
						int ret);
		void unblock_syscall();
	};
	std::unordered_map<int, PCB *> pcblist;


	std::multimap<in_port_t, in_addr_t> bindset;


private:
	virtual void timerCallback(void* payload) final;

public:
	TCPAssignment(Host* host);
	virtual void initialize();
	virtual void finalize();
	virtual ~TCPAssignment();

	void syscall_socket(UUID syscallUUID, int pid, int type, int protocol);
    void syscall_close(UUID syscallUUID, int pid, int sockfd);
    void syscall_bind(UUID syscallUUID, int pid, int sockfd, struct sockaddr *my_addr, socklen_t addrlen);
    void syscall_getsockname(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t *addrlen);
	void syscall_connect(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t addrlen);
	void syscall_getpeername(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t *addrlen);
	void syscall_listen(UUID syscallUUID, int pid, int sockfd, int backlog);
	void syscall_accept(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t *addrlen);
	void syscall_write(UUID syscallUUID, int pid, int sockfd, const void *buf, size_t count);
	void syscall_read(UUID syscallUUID,  int pid, int sockfd, const void *buf, size_t count);


	std::pair<int, int> get_pid_fd(in_addr_t src_addr, in_port_t src_port, in_addr_t dest_addr, in_port_t dest_port);
	std::pair<int, int> get_pid_fd_sock(Socket *sock);
	std::pair<int, int> get_listen_pid_fd(in_addr_t dest_addr, in_port_t dest_port);

	std::pair<in_addr_t, in_port_t> get_addr_port(struct sockaddr_in *info);
	struct sockaddr set_addr_port(in_addr_t addr, in_port_t port);

	void write_header(Packet *packet, Socket *sock, uint16_t flags);
	Packet *create_packet(Socket *sock, uint16_t flags, void *data, size_t data_len);
	void transmit_packet(Socket *sock, Packet *p, bool isACK, size_t count);
	void retransmit(Socket *sock, uint32_t seq);

	size_t writeBuf(Socket *sock, const void *buf, size_t count);

	void set_timeout(TimerPayload *timer, Time limit);
protected:
	virtual void systemCallback(UUID syscallUUID, int pid, const SystemCallParameter& param) final;
	virtual void packetArrived(std::string fromModule, Packet* packet) final;
};

class TCPAssignmentProvider
{
private:
	TCPAssignmentProvider() {}
	~TCPAssignmentProvider() {}
public:
	static HostModule* allocate(Host* host) { return new TCPAssignment(host); }
};

}


#endif /* E_TCPASSIGNMENT_HPP_ */
