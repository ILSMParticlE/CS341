/*
 * E_TCPAssignment.cpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: Keunhong Lee
 */


#include <E/E_Common.hpp>
#include <E/Networking/E_Host.hpp>
#include <E/Networking/E_Networking.hpp>
#include <cerrno>
#include <E/Networking/E_Packet.hpp>
#include <E/Networking/E_NetworkUtil.hpp>
#include "TCPAssignment.hpp"

namespace E
{

TCPAssignment::TCPAssignment(Host* host) : HostModule("TCP", host),
		NetworkModule(this->getHostModuleName(), host->getNetworkSystem()),
		SystemCallInterface(AF_INET, IPPROTO_TCP, host),
		NetworkLog(host->getNetworkSystem()),
		TimerModule(host->getSystem())
{

}

TCPAssignment::~TCPAssignment()
{

}

void TCPAssignment::initialize()
{

}

void TCPAssignment::finalize()
{

}

void TCPAssignment::systemCallback(UUID syscallUUID, int pid, const SystemCallParameter& param)
{
	switch(param.syscallNumber)
	{
	case SOCKET:
		this->syscall_socket(syscallUUID, pid, param.param1_int, param.param2_int);
		break;
	case CLOSE:
		this->syscall_close(syscallUUID, pid, param.param1_int);
		break;
	case READ:
		//this->syscall_read(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
		break;
	case WRITE:
		//this->syscall_write(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
		break;
	case CONNECT:
		this->syscall_connect(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr*>(param.param2_ptr), (socklen_t)param.param3_int);
		break;
	case LISTEN:
		this->syscall_listen(syscallUUID, pid, param.param1_int, param.param2_int);
		break;
	case ACCEPT:
		this->syscall_accept(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr*>(param.param2_ptr),
				static_cast<socklen_t*>(param.param3_ptr));
		break;
	case BIND:
		this->syscall_bind(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr *>(param.param2_ptr),
				(socklen_t) param.param3_int);
		break;
	case GETSOCKNAME:
		this->syscall_getsockname(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr *>(param.param2_ptr),
				static_cast<socklen_t*>(param.param3_ptr));
		break;
	case GETPEERNAME:
		this->syscall_getpeername(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr *>(param.param2_ptr),
				static_cast<socklen_t*>(param.param3_ptr));
		break;
	default:
		assert(0);
	}
}

void TCPAssignment::syscall_socket(UUID syscallUUID, int pid, int type, int protocol){
/*
   	if (type != SOCK_STREAM){
   		this->returnSystemCall(syscallUUID, -1);
		return;
   	}
	if (protocol != IPROTO_TCP){
		this->returnSystemCall(syscallUUID, -1);
		return;
	}
*/
	
	int fd;
	fd = this->createFileDescriptor(pid);

	// preserve data
	if (fd != -1){
		if (!pcblist.count(pid)) pcblist[pid] = new PCB;
		pcblist[pid]->fdlist[fd] = new Socket;
	}

	this->returnSystemCall(syscallUUID, fd);
}


void TCPAssignment::syscall_close(UUID syscallUUID, int pid, int sockfd){
	if (!pcblist.count(pid) || !pcblist[pid]->fdlist.count(sockfd)){
		this->returnSystemCall(syscallUUID, -1);
		return;
	}

	Socket *sock = pcblist[pid]->fdlist[sockfd];

	if (sock->state == S_ESTAB){
		// active close in 4-handshaking
		this->sendPacket("IPv4", create_packet(sock, FIN | ACK, nullptr, 0));
		sock->state = S_FIN_WAIT_1;
		sock->seq_send++;
	}
	else if (sock->state == S_CLOSE_WAIT){
		// passive close in 4-handshaking
		this->sendPacket("IPv4", create_packet(sock, FIN | ACK, nullptr, 0));
		sock->state = S_LAST_ACK;
		sock->seq_send++;
	}
	else{
		// closing isolated or bound, listen socket
		if (sock->bound){
			if (sock->state == S_LISTEN){
				// In my implementation, although I should send FINACK packet for established socket,
				// it is impossible since I didn't put them in PCB. I cannot find the matched socket
				// when packet is arrived to it...
				// So I'm going to delete them all... assume that there is no such cases...

				while (!sock->lq->pending.empty()){
					Socket *tmp_sock = sock->lq->pending.front();
					int tmp_fd = sock->lq->pending_fd.front();
					sock->lq->pending.pop(); sock->lq->pending_fd.pop();

					this->removeFileDescriptor(pid, tmp_fd);
					delete tmp_sock;
				}
			}

			// remove data in bindlist
		 	in_addr_t caddr = ((sockaddr_in *) &(sock->src))->sin_addr.s_addr;
			in_port_t cport = ((sockaddr_in *) &(sock->src))->sin_port;

			std::multimap<in_port_t, in_addr_t>::iterator it;
			for (it = bindset.lower_bound(cport); it != bindset.upper_bound(cport); it++){
				if (caddr == it->second){
					bindset.erase(it);
					break;
				}
			}
		}
		pcblist[pid]->fdlist.erase(sockfd);
		delete sock;
	}

	//pcblist[pid]->fdlist.erase(sockfd);
	this->removeFileDescriptor(pid, sockfd);
	this->returnSystemCall(syscallUUID, 0);
}


void TCPAssignment::syscall_bind(UUID syscallUUID, int pid,
				int sockfd, struct sockaddr *my_addr, socklen_t addrlen){
	if (!pcblist.count(pid) || !pcblist[pid]->fdlist.count(sockfd)){
		this->returnSystemCall(syscallUUID, -1);
		return;
	}

	in_addr_t bind_addr = ntohl(((sockaddr_in *) my_addr)->sin_addr.s_addr);
	in_port_t bind_port = ntohs(((sockaddr_in *) my_addr)->sin_port);

	Socket *sock = pcblist[pid]->fdlist[sockfd];
	// check already bound or not
	if (sock->bound){
		this->returnSystemCall(syscallUUID, -1);
		return;
	}
	
	// iterate bindlist to check whether overlapped addr exists
	std::multimap<in_port_t, in_addr_t>::iterator it;
	for (it = bindset.lower_bound(bind_port); it != bindset.upper_bound(bind_port); it++){
		if (bind_addr == INADDR_ANY || it->second == INADDR_ANY || bind_addr == it->second){
			this->returnSystemCall(syscallUUID, -1);
			return;
		}
	}

	// associate information to socket and update bindset;
	sock->bound = true;
	sock->src = set_addr_port(bind_addr, bind_port);
	bindset.insert(std::pair<in_port_t, in_addr_t> (bind_port, bind_addr));

	this->returnSystemCall(syscallUUID, 0);
}


void TCPAssignment::syscall_getsockname(UUID syscallUUID, int pid,
				int sockfd, struct sockaddr *addr, socklen_t *addr_len){
	if (!pcblist.count(pid) || !pcblist[pid]->fdlist.count(sockfd)){
		this->returnSystemCall(syscallUUID, -1);
		return;
	}

	in_addr_t saddr; in_port_t sport;
	std::tie(saddr, sport) = get_addr_port((sockaddr_in *) &(pcblist[pid]->fdlist[sockfd]->src));
	*addr = set_addr_port(saddr, sport);
	*addr_len = sizeof(*addr);
	this->returnSystemCall(syscallUUID, 0);
}


void TCPAssignment::syscall_connect(UUID syscallUUID, int pid, int sockfd,
				struct sockaddr *addr, socklen_t addrlen){
	if (!(pcblist[pid]->fdlist.count(sockfd))){
		this->returnSystemCall(syscallUUID, -1);
		return;
	}

	Socket *sock = pcblist[pid]->fdlist[sockfd];
	if (sock->state != S_CLOSED){
		this->returnSystemCall(syscallUUID, -1);
		return;
	}


	in_addr_t dest_addr;
	in_port_t dest_port;
	std::tie(dest_addr, dest_port) = get_addr_port((sockaddr_in *) addr);
	// fill remote data
	sock->dest = set_addr_port(dest_addr, dest_port);

	in_addr_t local_addr;
	in_port_t local_port;
	// implicit bind
	if (!sock->bound){
		in_addr_t remote_addr = ((sockaddr_in *)addr)->sin_addr.s_addr;
		int routing_table_port = this->getHost()->getRoutingTable((const uint8_t *) &remote_addr);
		if (!this->getHost()->getIPAddr((uint8_t *) &local_addr, routing_table_port)){	// get local ip address
			this->returnSystemCall(syscallUUID, -1);
			return;
		}
	
		while (true){	// get local port
			local_port = rand() % 65536;
			if (!bindset.count(local_port)) break;
			std::multimap<in_port_t, in_addr_t>::iterator it;
			for (it = bindset.lower_bound(local_port); it != bindset.upper_bound(local_port); it++){
				if (it->second == INADDR_ANY || it->second == local_addr || local_addr == INADDR_ANY) break;
			}
			if (it == bindset.end() || it->first != local_port) break;
		}

		local_addr = ntohl(local_addr);
		sock->src = set_addr_port(local_addr, local_port);
	}
	// send packet
	Packet *packet = create_packet(sock, SYN, nullptr, 0);
	sock->state = S_SYN_SENT;
	this->sendPacket("IPv4", packet);


	// increase current seq num
	sock->seq_send ++;

	// block system call
	(*pcblist[pid]).block_syscall(CONNECT, syscallUUID, sockfd, addr, addrlen, nullptr, 0);
}

void TCPAssignment::syscall_getpeername(UUID syscallUUID, int pid, int sockfd,
				struct sockaddr *addr, socklen_t *addrlen){
	if (!(pcblist[pid]->fdlist.count(sockfd))){
		this->returnSystemCall(syscallUUID, -1);
		return;
	}
	
	Socket *sock = pcblist[pid]->fdlist[sockfd];
	
	// need to check socket state??
	//if (sock->state != S_ESTAB){
	//	returnSystemCall(syscallUUID, -1);
	//	return;
	//}

	in_addr_t paddr; in_port_t pport;
	std::tie(paddr, pport) = get_addr_port((sockaddr_in *) &sock->dest);
	*addr = set_addr_port(paddr, pport);
	*addrlen = sizeof(*addr);
	returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_listen(UUID syscallUUID, int pid, int sockfd, int backlog){
	if (!pcblist.count(pid) || !pcblist[pid]->fdlist.count(sockfd)){
		this->returnSystemCall(syscallUUID, -1);
		return;
	}

	Socket *sock = pcblist[pid]->fdlist[sockfd];
	if (!sock->bound){
		this->returnSystemCall(syscallUUID, -1);
		return;
	}

	sock->lq = new ListenQueue(backlog);
	sock->state = S_LISTEN;
	this->returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_accept(UUID syscallUUID, int pid,
				int sockfd, struct sockaddr *addr, socklen_t *addrlen){
	if (!pcblist.count(pid) || !pcblist[pid]->fdlist.count(sockfd)){
		this->returnSystemCall(syscallUUID, -1);
		return;
	}

	Socket *sock = pcblist[pid]->fdlist[sockfd];
	if (sock->state != S_LISTEN){
		this->returnSystemCall(syscallUUID, -1);
		return;
	}

	// block syscall if there is no waiting
	if (sock->lq->pending.empty()){
		(*pcblist[pid]).block_syscall(ACCEPT, syscallUUID, sockfd, addr, 0, addrlen, 0);
		return;
	}

	// get duplicated socket
	Socket *sock_dup = sock->lq->pending.front();
	sock->lq->pending.pop();

	in_addr_t dest_addr = ((sockaddr_in *) &(sock_dup->dest))->sin_addr.s_addr;
	in_port_t dest_port = ((sockaddr_in *) &(sock_dup->dest))->sin_port;
	*addr = set_addr_port(htonl(dest_addr), htonl(dest_port));
	*addrlen = sizeof(sock_dup->dest);

	int fd = sock->lq->pending_fd.front();
	sock->lq->pending_fd.pop();
	sock_dup->state = S_ESTAB;
	this->returnSystemCall(syscallUUID, fd);
}



void TCPAssignment::packetArrived(std::string fromModule, Packet* packet)
{

	// fetch the destination socket
	in_addr_t src_addr, dest_addr;
	in_port_t src_port, dest_port;
	packet->readData(14+12, &src_addr, 4);
	packet->readData(14+16, &dest_addr, 4);
	packet->readData(34, &src_port, 2);
	packet->readData(36, &dest_port, 2);	// addr and port of "sender", not receiver
	src_addr = ntohl(src_addr); src_port = ntohs(src_port);
	dest_addr = ntohl(dest_addr); dest_port = ntohs(dest_port);


	uint16_t flags;
	packet->readData(34+12, &flags, 2);
	flags = htons(flags);

	int pid, sockfd;
	Packet *myPacket;

	//printf("%d %d\n", ntohs(src_port), ntohs(dest_port));;

	std::tie(pid, sockfd) = get_pid_fd(src_addr, src_port, dest_addr, dest_port);
	if (pid == -1 && sockfd == -1){
		// need to find listen state socket
		std::tie(pid, sockfd) = get_listen_pid_fd(dest_addr, dest_port);
		if (pid != -1 && sockfd != -1){
			Socket *sock_listen = pcblist[pid]->fdlist[sockfd];
		
			assert(sock_listen->state == S_LISTEN);
			if (!pcblist[pid]->block){
				if (sock_listen->lq->cur_backlog < sock_listen->lq->backlog){
					Socket *sock_dup = new Socket;
					sock_dup->src = set_addr_port(dest_addr, dest_port);
					sock_dup->dest = set_addr_port(src_addr, src_port);

					uint32_t seq_sender;
					packet->readData(34+4, &seq_sender, 4);
					seq_sender = ntohl(seq_sender);
					sock_dup->seq_recv = seq_sender + 1;

					sock_listen->lq->pending.push(sock_dup);

					int fd = this->createFileDescriptor(pid);
					sock_listen->lq->pending_fd.push(fd);
					pcblist[pid]->fdlist[fd] = sock_dup;
					sock_listen->lq->cur_backlog++;

					// send SYNACK
					Packet *myPacket = create_packet(sock_dup, SYN | ACK, nullptr, 0);
					sock_dup->state = S_SYN_RCVD;
					this->sendPacket("IPv4", myPacket);

					// increase seqnum
					sock_dup->seq_send++;
				}
				else{
					printf("backlog is full... maybe should reset\n");
				}
			}
			else{
				// accept it!
				PCB::blockedInfo *b = pcblist[pid]->blocked_info;
				assert(b->syscall == ACCEPT);

				int fd = this->createFileDescriptor(pid);
				Socket *sock_dup = new Socket;
				sock_dup->dest = set_addr_port(src_addr, src_port);
				sock_dup->src = set_addr_port(dest_addr, dest_port);

				uint32_t ack_sender;
				packet->readData(34+8, &ack_sender, 4);
				ack_sender = ntohl(ack_sender);
				
				uint32_t seq_sender;
				packet->readData(34+4, &seq_sender, 4);
				seq_sender = ntohl(seq_sender);
				sock_dup->seq_recv = seq_sender + 1;
	
				*(b->addr) = set_addr_port(dest_addr, dest_port);
				*(b->addr_len_ptr) = sizeof(sock_dup->dest);
				pcblist[pid]->fdlist[fd] = sock_dup;

				myPacket = create_packet(sock_dup, SYN | ACK, nullptr, 0);
				sock_dup->state = S_SYN_RCVD;
				this->sendPacket("IPv4", myPacket);
				sock_dup->seq_send ++;

				(*pcblist[pid]).block_syscall(ACCEPT, b->syscallUUID, b->sockfd, b->addr, 0, b->addr_len_ptr, fd);
			}
		}	
		this->freePacket(packet);
		return;
	}
	
	PCB::blockedInfo *b = pcblist[pid]->blocked_info;
	Socket *sock = pcblist[pid]->fdlist[sockfd];

	switch (sock->state){
		case S_SYN_SENT:
			// active open connection final step
			if ((flags & SYN) && (flags & ACK)){
				assert(pcblist[pid]->block);
				assert(b->syscall == CONNECT);

				this->returnSystemCall(b->syscallUUID, 0);
				pcblist[pid]->unblock_syscall();
				sock->state = S_ESTAB;
				
				// check ack from sender
				uint32_t ack_sender;
				packet->readData(34+8, &ack_sender, 4);
				ack_sender = ntohl(ack_sender);
				if (sock->seq_send != ack_sender) printf("fuck!\n");

				// get seq num from sender
				uint32_t seq_sender;
				packet->readData(34+4, &seq_sender, 4);
				seq_sender = ntohl(seq_sender);
				sock->seq_recv = seq_sender + 1;

				// send packet
				myPacket = create_packet(sock, ACK, nullptr, 0);
				this->sendPacket("IPv4", myPacket);

				// increase current seq num
				//sock->seq_send ++;
			}
			else if (flags & SYN){
				//simulatneous connect
				sock->state = S_SYN_SIMRCVD;
					
				assert(pcblist[pid]->block);
				assert(b->syscall == CONNECT);

				
				// check ack from sender
				uint32_t ack_sender;
				packet->readData(34+8, &ack_sender, 4);
				ack_sender = ntohl(ack_sender);
				//if (sock->seq_send != ack_sender) printf("fuck!123\n");

				// get seq num from sender
				uint32_t seq_sender;
				packet->readData(34+4, &seq_sender, 4);
				seq_sender = ntohl(seq_sender);
				sock->seq_recv = seq_sender + 1;

				// send packet
				sock->seq_send--;
				myPacket = create_packet(sock, SYN | ACK, nullptr, 0);
				this->sendPacket("IPv4", myPacket);

				// increase current seq num
				sock->seq_send ++;
			}
			break;
		case S_SYN_RCVD:
			if (flags & ACK){
				if (pcblist[pid]->block && b->syscall == ACCEPT){
					assert(pcblist[pid]->block);
					assert(b->syscall == ACCEPT);
					this->returnSystemCall(b->syscallUUID, b->ret);
					pcblist[pid]->unblock_syscall();
				}
				sock->state = S_ESTAB;
				
				// find listen socket
				int lpid, lfd;
				std::tie(lpid, lfd) = get_listen_pid_fd(dest_addr, dest_port);
				pcblist[lpid]->fdlist[lfd]->lq->cur_backlog--;

				// check ack from sender
				uint32_t ack_sender;
				packet->readData(34+8, &ack_sender, 4);
				ack_sender = ntohl(ack_sender);
				if (sock->seq_send != ack_sender) printf("fuck!!!\n");
			
				// get seq num from sender;
				uint32_t seq_sender;
				packet->readData(34+4, &seq_sender, 4);
				seq_sender = ntohl(seq_sender);
				//sock->seq_recv ++;

			}	
			break;
		case S_SYN_SIMRCVD:
			if (flags & ACK){
				this->returnSystemCall(b->syscallUUID, 0);
				pcblist[pid]->unblock_syscall();

				// check ack from sender
				uint32_t ack_sender;
				packet->readData(34+8, &ack_sender, 4);
				ack_sender = ntohl(ack_sender);
				if (sock->seq_send != ack_sender) printf("fuck!!!!!!\n");

				// get seq num from sender
				uint32_t seq_sender;
				packet->readData(34+4, &seq_sender, 4);
				seq_sender = ntohl(seq_sender);
				sock->seq_recv = seq_sender + 1;

				// send packet
				myPacket = create_packet(sock, ACK, nullptr, 0);
				this->sendPacket("IPv4", myPacket);

				sock->state = S_ESTAB;
			}
			break;
		case S_ESTAB:
			if ((flags & FIN) && (flags & ACK)){
				// get seq num from sender
				uint32_t seq_sender;
				packet->readData(34+4, &seq_sender, 4);
				seq_sender = ntohl(seq_sender);
				sock->seq_recv = seq_sender + 1;

				// send packet
				myPacket = create_packet(sock, ACK, nullptr, 0);
				this->sendPacket("IPv4", myPacket);

				sock->state = S_CLOSE_WAIT;
			}
			break;
		// active close
		case S_FIN_WAIT_1:
			if (flags & ACK){
				if (flags & FIN){
					// simultaneous close
					uint32_t seq_sender;
					packet->readData(34+4, &seq_sender, 4);
					seq_sender = ntohl(seq_sender);
					sock->seq_recv = seq_sender + 1;

					myPacket = create_packet(sock, ACK, nullptr, 0);
					this->sendPacket("IPv4", myPacket);

					sock->state = S_CLOSING;
				}
				else{
					// not simultaneous
					sock->state = S_FIN_WAIT_2;
				}
			}
			break;
		case S_FIN_WAIT_2:
			if ((flags & FIN) && (flags & ACK)){
				// get seq num from sender
				uint32_t seq_sender;
				packet->readData(34+4, &seq_sender, 4);
				seq_sender = ntohl(seq_sender);
				sock->seq_recv = seq_sender + 1;

				// send packet
				myPacket = create_packet(sock, ACK, nullptr, 0);
				this->sendPacket("IPv4", myPacket);

				sock->state = S_TIMED_WAIT;

				// timer check
				this->addTimer(sock, TimeUtil::makeTime(2, TimeUtil::MINUTE));
			}
			break;
		case S_CLOSING:
			assert(flags & ACK);
			sock->state = S_TIMED_WAIT;

			// timer check
			this->addTimer(sock, TimeUtil::makeTime(2, TimeUtil::MINUTE));
			break;
		case S_LAST_ACK:
			if (flags & ACK){
				pcblist[pid]->fdlist.erase(sockfd);
				
				std::multimap<in_port_t, in_addr_t>::iterator it;
				for (it = bindset.lower_bound(dest_port); it != bindset.upper_bound(dest_port); ++it){
					if (dest_addr == it->second){
						bindset.erase(it);
						break;
					}
				}
				delete sock;

			}
		default:
			break;
		
	}
	this->freePacket(packet);

}

void TCPAssignment::timerCallback(void* payload)
{
	Socket *sock = (Socket *) payload;
	int pid, fd;
	std::tie(pid, fd) = get_pid_fd_sock(sock);
	if (pid == -1 && fd == -1) printf("shit\n");
	else{
		pcblist[pid]->fdlist.erase(fd);
	}
}



/* ListenQueue construct and detroyer */
TCPAssignment::ListenQueue::ListenQueue(size_t size){
	this->cur_backlog = 0;
	this->backlog = size;
}
TCPAssignment::ListenQueue::~ListenQueue(){
}


/* Socket constructor and destroyer */
TCPAssignment::Socket::Socket(){
	memset(&src, 0, sizeof(src));
	memset(&dest, 0, sizeof(dest));
	bound = false;
	state = S_CLOSED;
	seq_send = rand();

	wnd_size = 51200;

	lq = nullptr;
}
TCPAssignment::Socket::~Socket(){
}

/*****************************************************************/
/*			 Iterate pcblist to find appropriate socket			 */
/*****************************************************************/
std::pair<int, int> TCPAssignment::get_pid_fd(in_addr_t src_addr, in_port_t src_port, in_addr_t dest_addr, in_port_t dest_port){
	std::unordered_map<int, PCB *>::iterator pcb_it;
	std::unordered_map<int, Socket *>::iterator fd_it;
	Socket *sock;

	for (pcb_it = pcblist.begin(); pcb_it != pcblist.end(); pcb_it++){
		for (fd_it = pcb_it->second->fdlist.begin(); fd_it != pcb_it->second->fdlist.end(); fd_it++){
			sock = fd_it->second;
			in_addr_t tmp_sa, tmp_da;
			in_port_t tmp_sp, tmp_dp;
			tmp_sa = ((sockaddr_in *) &(sock->src))->sin_addr.s_addr;
			tmp_sp = ((sockaddr_in *) &(sock->src))->sin_port;
			tmp_da = ((sockaddr_in *) &(sock->dest))->sin_addr.s_addr;
			tmp_dp = ((sockaddr_in *) &(sock->dest))->sin_port;
			if (src_addr == tmp_da && src_port == tmp_dp && dest_addr == tmp_sa && dest_port == tmp_sp)
					return std::make_pair(pcb_it->first, fd_it->first);
		}
	}
	return std::make_pair(-1, -1);
}

std::pair<int, int> TCPAssignment::get_pid_fd_sock(Socket *sock){
	in_addr_t saddr, daddr; in_port_t sport, dport;
	sockaddr_in *sinfo = (sockaddr_in *) &sock->src;
	sockaddr_in *dinfo = (sockaddr_in *) &sock->dest;
	saddr = sinfo->sin_addr.s_addr; sport = sinfo->sin_port;
	daddr = dinfo->sin_addr.s_addr; dport = dinfo->sin_port;

	return get_pid_fd(daddr, dport, saddr, sport);
}

std::pair<int, int> TCPAssignment::get_listen_pid_fd(in_addr_t dest_addr, in_port_t dest_port){
	std::unordered_map<int, PCB *>::iterator pcb_it;
	std::unordered_map<int, Socket *>::iterator fd_it;
	Socket *sock;
	
	for (pcb_it = pcblist.begin(); pcb_it != pcblist.end(); pcb_it++){
		//if (pcb_it-/second->block) continue;
		for (fd_it = pcb_it->second->fdlist.begin(); fd_it != pcb_it->second->fdlist.end(); fd_it++){
			sock = fd_it->second;
			in_addr_t tmp_sa;
			in_port_t tmp_sp;
			tmp_sa = ((sockaddr_in *) &(sock->src))->sin_addr.s_addr;
			tmp_sp = ((sockaddr_in *) &(sock->src))->sin_port;

			if (sock->state == S_LISTEN && (tmp_sa == INADDR_ANY || tmp_sa == dest_addr) && tmp_sp == dest_port)
					return std::make_pair(pcb_it->first, fd_it->first);
		}
	}
	return std::make_pair(-1,-1);
}



/*****************************************************************/
/*					 Get or set addr & port						 */
/*****************************************************************/

std::pair<in_addr_t, in_port_t> TCPAssignment::get_addr_port(struct sockaddr_in *info){
	in_addr_t addr = ntohl(info->sin_addr.s_addr);
	in_port_t port = ntohs(info->sin_port);
	return std::make_pair(addr,port);
}

struct sockaddr TCPAssignment::set_addr_port(in_addr_t addr, in_port_t port){
	// addr and port should be host ordered
	sockaddr_in info;
	memset(&info, 0, sizeof(info));
	info.sin_family = AF_INET;
	info.sin_addr.s_addr = addr;
	info.sin_port = port;
	return *(sockaddr *) &info;
}


/*****************************************************************/
/*				 Functions that handle packets					 */
/*****************************************************************/

void TCPAssignment::write_header(Packet *packet, Socket *sock, uint16_t flags){
	// write addr and port
	in_addr_t src_addr, dest_addr;
	in_port_t src_port, dest_port;
	std::tie(src_addr, src_port) = get_addr_port((sockaddr_in *) &(sock->src));
	std::tie(dest_addr, dest_port) = get_addr_port((sockaddr_in *) &(sock->dest));

	packet->writeData(14+12, &src_addr, 4);
	packet->writeData(14+16, &dest_addr, 4);

	packet->writeData(34, &src_port, 2);
	packet->writeData(34+2, &dest_port, 2);

	// write seq and ACKnum
	uint32_t seqnum = htonl(sock->seq_send);
	uint32_t ACKnum = htonl(sock->seq_recv);
	packet->writeData(34+4, &(seqnum), 4);	// seqnum
	packet->writeData(34+8, &(ACKnum), 4); // ACKnum

	// write tcp_header_len and flags
	uint16_t f = flags | (5 << 12);
	f = htons(f);
	packet->writeData(34+12, &f, 2);

	// TODO : write receive window
	uint16_t wnd_size = sock->wnd_size;
	wnd_size = htons(wnd_size);
	packet->writeData(34+14, &wnd_size, 2);
}

Packet *TCPAssignment::create_packet(Socket *sock, uint16_t flags, void *data, size_t data_len){
	Packet *new_packet = this->allocatePacket(54+data_len);
	write_header(new_packet, sock, flags);

	// TODO : write data
	// will do at Lab3

	// write checksum
	uint32_t src_addr, dest_addr;
	uint8_t tcpbuf[20+data_len];
	new_packet->readData(14+12, &src_addr, 4);
	new_packet->readData(14+16, &dest_addr, 4);
	new_packet->readData(34, tcpbuf, 20+data_len);

	uint16_t checksum = NetworkUtil::tcp_sum(src_addr, dest_addr, tcpbuf, 20+data_len);
	checksum = ~checksum;
	checksum = htons(checksum);
	new_packet->writeData(34 + 16, &checksum, 2);

	return new_packet;
}



/*****************************************************************/
/*					 Block and unblock syscall					 */
/*****************************************************************/

void TCPAssignment::PCB::block_syscall(SystemCall syscall, UUID syscallUUID, int sockfd,
				struct sockaddr *addr, socklen_t addr_len, socklen_t *addr_len_ptr, int ret){
	this->block = true;
	this->blocked_info = new blockedInfo;
	
	// save information
	this->blocked_info->syscall = syscall;
	this->blocked_info->syscallUUID = syscallUUID;
	this->blocked_info->sockfd = sockfd;
	this->blocked_info->addr = addr;
	this->blocked_info->addr_len = addr_len;
	this->blocked_info->addr_len_ptr = addr_len_ptr;
	this->blocked_info->ret = ret;


	return;
}

void TCPAssignment::PCB::unblock_syscall(){
	delete this->blocked_info;
	this->blocked_info = new struct blockedInfo;
	this->block = false;

	return;
}


}
