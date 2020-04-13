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
		//this->syscall_connect(syscallUUID, pid, param.param1_int,
		//		static_cast<struct sockaddr*>(param.param2_ptr), (socklen_t)param.param3_int);
		break;
	case LISTEN:
		//this->syscall_listen(syscallUUID, pid, param.param1_int, param.param2_int);
		break;
	case ACCEPT:
		//this->syscall_accept(syscallUUID, pid, param.param1_int,
		//		static_cast<struct sockaddr*>(param.param2_ptr),
		//		static_cast<socklen_t*>(param.param3_ptr));
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
		//this->syscall_getpeername(syscallUUID, pid, param.param1_int,
		//		static_cast<struct sockaddr *>(param.param2_ptr),
		//		static_cast<socklen_t*>(param.param3_ptr));
		break;
	default:
		assert(0);
	}
}

// Lab1 new code begin
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
		if (!pcblist.count(pid)) pcblist[pid] = new pcb;
		pcblist[pid]->fdlist[fd] = new socket;
	}

	this->returnSystemCall(syscallUUID, fd);
}


void TCPAssignment::syscall_close(UUID syscallUUID, int pid, int sockfd){
	socket *sock = pcblist[pid]->fdlist[sockfd];
	
	in_addr_t caddr = ntohl(((sockaddr_in *) &(sock->src))->sin_addr.s_addr);
    in_port_t cport = ntohs(((sockaddr_in *) &(sock->src))->sin_port);

	// remove data in bindlist
	std::multimap<in_port_t, in_addr_t>::iterator it;
	for (it = bindset.lower_bound(cport); it != bindset.upper_bound(cport); it++){
		if (caddr == it->second){
			bindset.erase(it);
			break;
		}
	}
	
	
	// remove data in fdlist
	delete pcblist[pid]->fdlist[sockfd];
	pcblist[pid]->fdlist.erase(sockfd);

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

	
	socket *sock = pcblist[pid]->fdlist[sockfd];
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
	sock->src = *my_addr;
	bindset.insert(std::pair<in_port_t, in_addr_t> (bind_port, bind_addr));

	this->returnSystemCall(syscallUUID, 0);
}


void TCPAssignment::syscall_getsockname(UUID syscallUUID, int pid,
				int sockfd, struct sockaddr *addr, socklen_t *addr_len){
	if (!pcblist.count(pid) || !pcblist[pid]->fdlist.count(sockfd)){
		this->returnSystemCall(syscallUUID, -1);
		return;
	}
	
	*addr = pcblist[pid]->fdlist[sockfd]->src;
	*addr_len = sizeof(*addr);
	this->returnSystemCall(syscallUUID, 0);
}



void TCPAssignment::packetArrived(std::string fromModule, Packet* packet)
{

}

void TCPAssignment::timerCallback(void* payload)
{

}


}
