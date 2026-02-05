
export enum Protocol {
  TCP = 'TCP',
  UDP = 'UDP',
  ARP = 'ARP',
  ICMP = 'ICMP',
  DNS = 'DNS'
}

export enum AttackType {
  SYN_FLOOD = 'SYN Flood',
  PORT_SCAN = 'Port Scan',
  ARP_SPOOFING = 'ARP Spoofing',
  UDP_FLOOD = 'UDP Flood',
  NORMAL = 'Normal'
}

export interface User {
  id: string;
  username: string;
  role: 'Administrateur' | 'Analyste';
  lastLogin: string;
}

export interface Packet {
  timestamp: string;
  sourceIp: string;
  destIp: string;
  protocol: Protocol;
  attackType: AttackType;
  length: number;
}
