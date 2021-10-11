from iputils import *


class IP:
    def __init__(self, enlace):
        """
        Inicia a camada de rede. Recebe como argumento uma implementação
        de camada de enlace capaz de localizar os next_hop (por exemplo,
        Ethernet com ARP).
        """
        self.callback = None
        self.enlace = enlace
        self.enlace.registrar_recebedor(self.__raw_recv)
        self.ignore_checksum = self.enlace.ignore_checksum
        self.meu_endereco = None
        self.tabela = {}

    def __raw_recv(self, datagrama):
        dscp, ecn, identification, flags, frag_offset, ttl, proto, src_addr, dst_addr, payload = \
            read_ipv4_header(datagrama)
        if dst_addr == self.meu_endereco:
            # atua como host
            if proto == IPPROTO_TCP and self.callback:
                self.callback(src_addr, dst_addr, payload)
        else:
            # atua como roteador
            next_hop = self._next_hop(dst_addr)
            ttl -= 1

            if ttl > 0:
                datagrama = self._make_header(len(payload), src_addr, dst_addr, ttl, IPPROTO_TCP) + payload
            else:
                next_hop = self._next_hop(src_addr)
                datagrama_original = datagrama

                datagrama = self._make_header(28, self.meu_endereco, src_addr, 64, IPPROTO_ICMP)

                icmp_time_exceeded = struct.pack('!BBHHH', 11, 0, 0, 0, 0)
                checksum3 = calc_checksum(datagrama + icmp_time_exceeded)
                icmp_time_exceeded = struct.pack('!BBHHH', 11, 0, checksum3, 0, 0)

                datagrama = datagrama + icmp_time_exceeded + datagrama_original[:28]

            self.enlace.enviar(datagrama, next_hop)

    def _get_bin_addr(self, addr):
        return "".join([bin(int(x) + 256)[3:] for x in addr.split('.')])

    def _next_hop(self, dest_addr):
        dest_addr_bin = self._get_bin_addr(dest_addr)
        # print(f"dest addr {dest_addr_bin}")

        res = None
        max_n = -1
        for elem_tabela in self.tabela:
            cidr, n = elem_tabela[0].split('/')
            n = int(n)

            cidr_bin = self._get_bin_addr(cidr)

            if cidr_bin[:n] == dest_addr_bin[:n] and n > max_n:
                max_n = n
                res = elem_tabela[1]

        return res

    def definir_endereco_host(self, meu_endereco):
        """
        Define qual o endereço IPv4 (string no formato x.y.z.w) deste host.
        Se recebermos datagramas destinados a outros endereços em vez desse,
        atuaremos como roteador em vez de atuar como host.
        """
        self.meu_endereco = meu_endereco

    def definir_tabela_encaminhamento(self, tabela):
        """
        Define a tabela de encaminhamento no formato
        [(cidr0, next_hop0), (cidr1, next_hop1), ...]

        Onde os CIDR são fornecidos no formato 'x.y.z.w/n', e os
        next_hop são fornecidos no formato 'x.y.z.w'.
        """
        self.tabela = tabela

        # print("tabela %s" % self.tabela)

    def registrar_recebedor(self, callback):
        """
        Registra uma função para ser chamada quando dados vierem da camada de rede
        """
        self.callback = callback

    def _make_header(self, len_seg, src, dest, ttl, ip_proto):
        s = int.from_bytes(str2addr(src), "big")
        d = int.from_bytes(str2addr(dest), "big")
        header = struct.pack('!BBHHHBBHII',
                             (4 << 4) | 5, 0, len_seg + 20, 0, 0, ttl, ip_proto, 0, s, d)
        checksum = calc_checksum(header)
        return struct.pack('!BBHHHBBHII',
                           (4 << 4) | 5, 0, len_seg + 20, 0, 0, ttl, ip_proto, checksum, s, d)

    def enviar(self, segmento, dest_addr):
        """
        Envia segmento para dest_addr, onde dest_addr é um endereço IPv4
        (string no formato x.y.z.w).
        """
        next_hop = self._next_hop(dest_addr)

        self.enlace.enviar(
            self._make_header(len(segmento), self.meu_endereco, dest_addr, 64, IPPROTO_TCP) + segmento,
            next_hop
        )
