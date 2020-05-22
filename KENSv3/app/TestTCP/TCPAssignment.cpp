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
		this->syscall_read(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
		break;
	case WRITE:
		this->syscall_write(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
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

	//printf("close syscall\n");
	Socket *sock = pcblist[pid]->fdlist[sockfd];

	//printf("sock state in close %d\n", sock->state);
	if (sock->state == S_ESTAB){
		// active close in 4-handshaking
		Packet *myPacket = create_packet(sock, FIN | ACK, nullptr, 0);
		transmit_packet(sock, myPacket, false, 0);
		sock->state = S_FIN_WAIT_1;
	}
	else if (sock->state == S_CLOSE_WAIT){
		// passive close in 4-handshaking
		Packet *myPacket = create_packet(sock, FIN | ACK, nullptr, 0);
		transmit_packet(sock, myPacket, false, 0);
		sock->state = S_LAST_ACK;
	}
	else{
		// closing isolated or bound, listen socket
		if (sock->bound){
			if (sock->state == S_LISTEN){
				// In my implementation, although I should send FINACK packet for established socket,
				// it is impossible since I didn't put them in PCB. I cannot find the matched socket
				// when packet is arrived to it...
				// So I'm going to delete them all... assume that there are no such cases...

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
	transmit_packet(sock, packet, false, 0);

	// block system call
	(*pcblist[pid]).block_syscall(CONNECT, syscallUUID, sockfd, addr, addrlen, nullptr, nullptr, 0, 0);
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
		(*pcblist[pid]).block_syscall(ACCEPT, syscallUUID, sockfd, addr, 0, addrlen, nullptr, 0, 0);
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

void TCPAssignment::syscall_write(UUID syscallUUID,  int pid, int sockfd, const void *buf, size_t count){
	if (!pcblist.count(pid) || !pcblist[pid]->fdlist.count(sockfd)){
		this->returnSystemCall(syscallUUID, -1);
		return;
	}


	Socket *sock = pcblist[pid]->fdlist[sockfd];
	//if (sock->state != S_ESTAB){
	//	this->returnSystemCall(syscallUUID, -1);
	//	return;
	//}


	if (count == 0){
		this->returnSystemCall(syscallUUID, 0);
		return;
	}

	int ret = (int) writeBuf(sock, buf, count);
	if (ret == 0){
		// cannot write, buffer is full!
		(*pcblist[pid]).block_syscall(WRITE, syscallUUID, sockfd, nullptr, 0, nullptr, buf, count, 0);
		return;
	}

	this->returnSystemCall(syscallUUID, ret);
}

void TCPAssignment::syscall_read(UUID syscallUUID,  int pid, int sockfd, const void *buf, size_t count){
	if (!pcblist.count(pid) || !pcblist[pid]->fdlist.count(sockfd)){
		this->returnSystemCall(syscallUUID, -1);
		return;
	}

	Socket *sock = pcblist[pid]->fdlist[sockfd];
	//if (sock->state != S_ESTAB){
	//	this->returnSystemCall(syscallUUID, -1);
	//	return;
	//}

	if (count == 0){
		this->returnSystemCall(syscallUUID, 0);
		return;
	}

	int ret = (int) sock->readBuf(buf, count);
	if (ret == 0){
		// block system call
		(*pcblist[pid]).block_syscall(READ, syscallUUID, sockfd, nullptr, 0, nullptr, buf, count, 0);
		return;
	}
	this->returnSystemCall(syscallUUID, ret);
}




void TCPAssignment::packetArrived(std::string fromModule, Packet* packet)
{

	// fetch the destination socket
	in_addr_t src_addr, dest_addr;
	in_port_t src_port, dest_port;
	packet->readData(14+12, &src_addr, 4);
	packet->readData(14+16, &dest_addr, 4);
	packet->readData(34, &src_port, 2);
	packet->readData(34+2, &dest_port, 2);	// addr and port of "sender", not receiver
	src_addr = ntohl(src_addr); src_port = ntohs(src_port);
	dest_addr = ntohl(dest_addr); dest_port = ntohs(dest_port);

	uint32_t seq_sender, ack_sender;
	packet->readData(34+4, &seq_sender, 4);
	packet->readData(34+8, &ack_sender, 4);
	seq_sender = ntohl(seq_sender);
	ack_sender = ntohl(ack_sender);

	uint16_t flags;
	packet->readData(34+12, &flags, 2);
	flags = htons(flags);

	int pid, sockfd;
	Packet *myPacket;

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

					sock_dup->seq_recv = seq_sender + 1;

					sock_listen->lq->pending.push(sock_dup);

					int fd = this->createFileDescriptor(pid);
					sock_listen->lq->pending_fd.push(fd);
					pcblist[pid]->fdlist[fd] = sock_dup;
					sock_listen->lq->cur_backlog++;

					// send SYNACK
					Packet *myPacket = create_packet(sock_dup, SYN | ACK, nullptr, 0);
					sock_dup->state = S_SYN_RCVD;
					transmit_packet(sock_dup, myPacket, false, 0);
					
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

				sock_dup->seq_recv = seq_sender + 1;
	
				*(b->addr) = set_addr_port(dest_addr, dest_port);
				*(b->addr_len_ptr) = sizeof(sock_dup->dest);
				pcblist[pid]->fdlist[fd] = sock_dup;

				myPacket = create_packet(sock_dup, SYN | ACK, nullptr, 0);
				sock_dup->state = S_SYN_RCVD;
				transmit_packet(sock_dup, myPacket, false, 0);

				(*pcblist[pid]).block_syscall(ACCEPT, b->syscallUUID, b->sockfd, b->addr, 0, b->addr_len_ptr, nullptr, 0, fd);
			}
		}	
		this->freePacket(packet);
		return;
	}
	
	PCB::blockedInfo *b = pcblist[pid]->blocked_info;
	Socket *sock = pcblist[pid]->fdlist[sockfd];

	// read opponent's window size
	uint16_t swnd;
	packet->readData(34+14, &swnd, 2);
	sock->swnd = ntohs(swnd);

	uint16_t data_len;
	packet->readData(14+2, &data_len, 2);
	data_len = ntohs(data_len) - 40;

	// 200522 code begin
	if (flags & ACK){
		if (sock->acktop.count(ack_sender)){
			sock->last_ack = ack_sender;
			sock->dup_ack = 1;
			uint32_t seq;
			while (true){
				seq = sock->unacked.front();
				
				// delete previous packets' information
				if (sock->seqn_to_len.count(seq)){
					sock->in_flight -= sock->seqn_to_len[seq];
					printf("[2. receiving inflight %d]\n", sock->in_flight);
					assert(sock->in_flight >= 0);
					sock->seqn_to_len.erase(seq);
				}
				sock->unacked.erase(sock->unacked.begin());
				this->freePacket(sock->acktop[seq]);
				sock->acktop.erase(seq);

				// shut down timer
				TimerPayload *timer = sock->timerlist[seq];
				this->cancelTimer(timer->tUUID);
				sock->timerlist.erase(seq);
				delete timer;

				if (seq == ack_sender) break;
			}
			assert(!sock->acktop.count(ack_sender));
		}
		else{
			// retransmission detected
			// case 1. SYNACK, FINACK retransmission detected
			if (flags & SYN && !(sock->state == S_SYN_SENT || sock->state == S_SYN_SIMRCVD)){
				uint32_t send_tmp, recv_tmp;
				send_tmp = sock->seq_send; recv_tmp = sock->seq_recv;
				sock->seq_send = ack_sender;
				sock->seq_recv = seq_sender + 1;
				Packet *reACK = create_packet(sock, ACK, nullptr, 0);
				transmit_packet(sock, reACK, true, 0);
				sock->seq_send = send_tmp;
				sock->seq_recv = recv_tmp;
			}
			if (flags & FIN && !(sock->state == S_ESTAB || sock->state == S_FIN_WAIT_1 || sock->state == S_FIN_WAIT_2)){
				uint32_t send_tmp, recv_tmp;
				send_tmp = sock->seq_send; recv_tmp = sock->seq_recv;
				sock->seq_send = ack_sender;
				sock->seq_recv = seq_sender + 1;
				if (sock->close_sim) sock->seq_send ++;
				Packet *reACK = create_packet(sock, ACK, nullptr, 0);
				transmit_packet(sock, reACK, true, 0);
				sock->seq_send = send_tmp;
				sock->seq_recv = recv_tmp;
			}
			
			// case 2. duplicated ACK
			if (flags == ((5 << 12) | ACK) && data_len == 0){
				printf("/ I GOT IT /\n");
				if (sock->last_ack == ack_sender){
					printf("dupack %d\n", sock->dup_ack);
					sock->dup_ack ++;
					if (sock->dup_ack == 3){
						printf("case 1\n");
						
						std::vector<uint32_t>::iterator it;
						for (it = sock->unacked.begin(); it != sock->unacked.end(); ++it){
							printf("* retransmit %d\n", *it);
							retransmit(sock, *it);	
						}
					}
				}
				else{
					printf("something wrong...?\n");
				}
				


			}

		}
	}


	// 200522 code end

	switch (sock->state){
		case S_SYN_SENT:
			// active open connection final step
			if ((flags & SYN) && (flags & ACK)){
				assert(pcblist[pid]->block);
				assert(b->syscall == CONNECT);

				this->returnSystemCall(b->syscallUUID, 0);
				pcblist[pid]->unblock_syscall();
				sock->state = S_ESTAB;
				
				if (sock->seq_send != ack_sender) printf("fuck!\n");

				sock->seq_recv = seq_sender + 1;

				// send packet
				myPacket = create_packet(sock, ACK, nullptr, 0);
				transmit_packet(sock, myPacket, true, 0);
			}
			else if (flags & SYN){
				//simulatneous connect
				sock->state = S_SYN_SIMRCVD;
					
				assert(pcblist[pid]->block);
				assert(b->syscall == CONNECT);
			
				assert(sock->unacked.size() == 1);
				sock->acktop.erase(sock->unacked.front());
				sock->unacked.erase(sock->unacked.begin());
				TimerPayload *timer = sock->timerlist.begin()->second;
				this->cancelTimer(timer->tUUID);
				sock->timerlist.erase(sock->timerlist.begin());
				delete timer;
				
				sock->seq_recv = seq_sender + 1;

				// send packet
				sock->seq_send--;
				myPacket = create_packet(sock, SYN | ACK, nullptr, 0);
				transmit_packet(sock, myPacket, false, 0);
			}
			break;
		case S_SYN_RCVD:
			if ((flags & FIN) && (flags & ACK)){
				sock->state = S_CLOSE_WAIT;
			}
			else if (flags & ACK){
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

				if (sock->seq_send != ack_sender) printf("fuck!!!\n");
			
				seq_sender = ntohl(seq_sender);

			}	
			break;
		case S_SYN_SIMRCVD:
			if (flags & ACK){
				assert(!(flags & FIN));
				this->returnSystemCall(b->syscallUUID, 0);
				pcblist[pid]->unblock_syscall();

				if (sock->seq_send != ack_sender) printf("fuck!!!!!!\n");

				// if get SYNACK send packet
				if (flags & SYN){
					sock->seq_recv = seq_sender + 1;
					myPacket = create_packet(sock, ACK, nullptr, 0);
					transmit_packet(sock, myPacket, true, 0);
				}

				sock->state = S_ESTAB;
			}
			break;
		case S_ESTAB:	
			if ((flags & FIN) && (flags & ACK)){
				sock->seq_recv = seq_sender + 1;

				// send packet
				myPacket = create_packet(sock, ACK, nullptr, 0);
				transmit_packet(sock, myPacket, true, 0);
				sock->state = S_CLOSE_WAIT;

				// if there is remaining blocked systemcall, break it
				if (pcblist[pid]->block){
					this->returnSystemCall(pcblist[pid]->blocked_info->syscallUUID, -1);
				}

			}

			// read and write
			else if (flags & ACK){
				// get data length
			
				/*
				if (data_len == 0){	
					// 3-2 TODO : check inflight algorithm
					if (sock->seqn_to_len.count(ack_sender)){
						sock->in_flight -= sock->seqn_to_len[ack_sender];
						assert(sock->in_flight >= 0);
					}
				}
				*/

				if (data_len > 0){
					packet->readData(54, (uint8_t *)sock->rbuf + sock->buf_size, data_len);
					sock->buf_size += data_len;
					sock->rwnd -= data_len;
					assert(sock->rwnd >= 0 && sock->rwnd <= 51200);

				}


				// unblock syscall
				if (pcblist[pid]->block){
					PCB::blockedInfo *b = pcblist[pid]->blocked_info;
					if (b->syscall == WRITE){
						if (sock->swnd - sock->in_flight > 0 && sock->in_flight < 51200){ // 3-2 TODO :in flight, not received ACK...
							int ret = (int) writeBuf(sock, b->buf, b->count);
							assert(ret > 0);
							this->returnSystemCall(b->syscallUUID, ret);
							pcblist[pid]->unblock_syscall();
						}
					}
					else if (b->syscall == READ){
						if (sock->buf_size > 0){
							int ret = (int) sock->readBuf(b->buf, b->count);
							assert(ret > 0);
							this->returnSystemCall(b->syscallUUID, ret);
							pcblist[pid]->unblock_syscall();
						}
					}
				}

				// applying change in window, and send ACK
				if (data_len > 0){
					sock->seq_recv += data_len;
					myPacket = create_packet(sock, ACK, nullptr, 0);
					transmit_packet(sock, myPacket, true, 0);
				}
			}

			break;
		// active close
		case S_FIN_WAIT_1:
			if (flags & ACK){
				if (flags & FIN){
					// simultaneous close
					sock->seq_recv = seq_sender + 1;
					myPacket = create_packet(sock, ACK, nullptr, 0);
					transmit_packet(sock, myPacket, true, 0);
					
					sock->close_sim = true;
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
				sock->seq_recv = seq_sender + 1;
				sock->state = S_TIMED_WAIT;

				// send packet
				myPacket = create_packet(sock, ACK, nullptr, 0);
				transmit_packet(sock, myPacket, true, 0);
			}
			break;
		case S_CLOSING:{
			assert(flags & ACK);
			sock->state = S_TIMED_WAIT;

			// add timer
			TimerPayload *finaltimer = new TimerPayload(false);
			finaltimer->sock = sock;
			set_timeout(finaltimer, TimeUtil::makeTime(2, TimeUtil::MINUTE));

			break;
		}
		case S_LAST_ACK:
			if ((flags & ACK) && !(flags & FIN)){
				// 3-2 TODO : check ack and indicate whether it is last ack or not
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
	TimerPayload *timer = (TimerPayload *) payload;
	Socket *sock = timer->sock;
	if (timer->retransmit){
		uint32_t seq = timer->seq;
		// printf("case 2\n");
		//if (sock->timerlist.count(seq)) retransmit(sock, seq);
		retransmit(sock, seq);
		
	}
	else{
		assert(sock->state == S_TIMED_WAIT);
		int pid, fd;
		std::tie(pid, fd) = get_pid_fd_sock(sock);
		if (pid == -1 && fd == -1) printf("shit\n");
		else{
			pcblist[pid]->fdlist.erase(fd);
		}
	}
}


/*****************************************************************/
/*				Constructor and Destoyer of classes 			 */
/*****************************************************************/

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

	rwnd = 51200;
	buf_size = 0;
	rbuf = malloc(max_wnd);
	in_flight = 0;
	dup_ack = 0;
	last_ack = 0;

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

	// write rwnd
	uint16_t rwnd = sock->rwnd;
	rwnd = htons(rwnd);
	packet->writeData(34+14, &rwnd, 2);
}

Packet *TCPAssignment::create_packet(Socket *sock, uint16_t flags, void *data, size_t data_len){
	Packet *new_packet = this->allocatePacket(54+data_len);
	write_header(new_packet, sock, flags);

	// TODO : write data
	new_packet->writeData(54, data, data_len);

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

void TCPAssignment::transmit_packet(Socket *sock, Packet *p, bool isACK, size_t count){
	// when data length is zero
	if (isACK){
		this->sendPacket("IPv4", p);
		return;
	}

	size_t seq_inc = count? count : 1;

	// send a packet that include some data
	Packet *clone = this->clonePacket(p);
	this->sendPacket("IPv4", p);
	sock->seq_send += seq_inc;
	sock->unacked.push_back(sock->seq_send);
	assert(!sock->acktop.count(sock->seq_send));
	sock->acktop[sock->seq_send] = clone;

	// set timer
	TimerPayload *timer = new TimerPayload(true);
	if (sock->state == S_TIMED_WAIT) timer->retransmit = false;
	// 4 TODO : sample RTT and estimated RTT
	timer->sock = sock;
	timer->seq = sock->seq_send;
	Time limit = sock->state == S_TIMED_WAIT? TimeUtil::makeTime(2, TimeUtil::MINUTE) : TimeUtil::makeTime(100, TimeUtil::MSEC);
	set_timeout(timer, limit);
	sock->timerlist[sock->seq_send] = timer;
	
	if (count > 0){
		sock->in_flight += count;
		printf("[transmit inflight %d]\n", sock->in_flight);
		assert(!sock->seqn_to_len.count(sock->seq_send));
		sock->seqn_to_len[sock->seq_send] = count;
	}
	
	return;
}

void TCPAssignment::retransmit(Socket *sock, uint32_t seq){
	// reset timer
	assert(sock->timerlist.count(seq));
	TimerPayload *timer = sock->timerlist[seq];
	this->cancelTimer(timer->tUUID);
	delete timer;
	TimerPayload *new_timer = new TimerPayload(true);
	new_timer->sock = sock;
	new_timer->seq = seq;
	set_timeout(new_timer, TimeUtil::makeTime(100, TimeUtil::MSEC));
	sock->timerlist[seq] = new_timer;

	Packet *retransmit = this->clonePacket(sock->acktop[seq]);
	this->sendPacket("IPv4", retransmit);
}


/*****************************************************************/
/*					 Functions handle buffers					 */
/*****************************************************************/

size_t TCPAssignment::writeBuf(Socket *sock, const void *buf, size_t count){
	size_t ret = 0;
	uint8_t *data = (uint8_t *) buf;

	// 3-2 TODO : check cnt

	//assert(sock->swnd > 0);
	size_t cnt = count >= sock->swnd - sock->in_flight? sock->swnd - sock->in_flight : count;
	if (sock->in_flight + cnt > 51200) cnt = 51200 - sock->in_flight;
	if (sock->in_flight == 51200) cnt = 0;
	while (cnt > 0){
		size_t data_len = cnt > 512? 512 : cnt;

		Packet *p = create_packet(sock, ACK, data, data_len);
		transmit_packet(sock, p, false, data_len);

		data += data_len;
		ret += data_len;
		cnt -= data_len;
	}
	return ret;
}

size_t TCPAssignment::Socket::readBuf(const void *buf, size_t count){
	
	void *new_rbuf = malloc(max_wnd);
	memset(new_rbuf, 0, max_wnd);

	size_t rdata_len = count >= buf_size? buf_size: count;
	memcpy((void *)buf, rbuf, rdata_len);
	buf_size -= rdata_len;
	rwnd += rdata_len;

	memcpy(new_rbuf, (uint8_t *)rbuf + rdata_len, buf_size);

	void *dbuf = rbuf;
	rbuf = new_rbuf;
	free(dbuf);

	return rdata_len;
}



/*****************************************************************/
/*					 Block and unblock syscall					 */
/*****************************************************************/

void TCPAssignment::PCB::block_syscall(SystemCall syscall, UUID syscallUUID, int sockfd,
				struct sockaddr *addr, socklen_t addr_len, socklen_t *addr_len_ptr,
				const void *buf, size_t count,
				int ret){
	this->block = true;
	this->blocked_info = new blockedInfo;
	
	// save information
	this->blocked_info->syscall = syscall;
	this->blocked_info->syscallUUID = syscallUUID;
	this->blocked_info->sockfd = sockfd;
	this->blocked_info->addr = addr;
	this->blocked_info->addr_len = addr_len;
	this->blocked_info->addr_len_ptr = addr_len_ptr;

	this->blocked_info->buf = buf;
	this->blocked_info->count = count;

	this->blocked_info->ret = ret;


	return;
}

void TCPAssignment::PCB::unblock_syscall(){
	delete this->blocked_info;
	this->blocked_info = new struct blockedInfo;
	this->block = false;

	return;
}


/*****************************************************************/
/*					 Timer Handling Functions					 */
/*****************************************************************/

TCPAssignment::TimerPayload::TimerPayload(bool isRetransmit){
	retransmit = isRetransmit;
}

TCPAssignment::TimerPayload::~TimerPayload(){
}

void TCPAssignment::set_timeout(TimerPayload *timer, Time limit){
	timer->sent = this->getHost()->getSystem()->getCurrentTime();
	timer->timeout = limit;
	timer->tUUID = this->addTimer(timer, limit);
}


}
