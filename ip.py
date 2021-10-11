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
        dscp, ecn, identification, flags, frag_offset, ttl, proto, \
        src_addr, dst_addr, payload = read_ipv4_header(datagrama)
        if dst_addr == self.meu_endereco:
            # atua como host
            if proto == IPPROTO_TCP and self.callback:
                self.callback(src_addr, dst_addr, payload)
        else:
            # atua como roteador
            next_hop = self._next_hop(dst_addr)
            # TODO: Trate corretamente o campo TTL do datagrama
            self.enlace.enviar(datagrama, next_hop)

    def _next_hop(self, dest_addr):
        # TODO: Use a tabela de encaminhamento para determinar o próximo salto
        # (next_hop) a partir do endereço de destino do datagrama (dest_addr).
        # Retorne o next_hop para o dest_addr fornecido.
        dest_addr_bin = "".join([bin(int(x) + 256)[3:] for x in dest_addr.split('.')])
        # print(f"dest addr {dest_addr_bin}")

        for elem_tabela in self.tabela:
            cidr, n = elem_tabela[0].split('/')
            n = int(n)

            cidr_bin = "".join([bin(int(x) + 256)[3:] for x in cidr.split('.')])

            if cidr_bin[:n] == dest_addr_bin[:n]:
                return elem_tabela[1]

        return None

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

    def _make_header(self, seg, src, dest):
        s = int.from_bytes(str2addr(src), "big")
        d = int.from_bytes(str2addr(dest), "big")
        header = struct.pack('!BBHHHBBHII',
                             (4 << 4) | 5, (0 << 6) | 0, len(seg) + 20, 0, 0, 64, 6, 0, s, d)
        checksum = calc_checksum(header)
        return struct.pack('!BBHHHBBHII',
                           (4 << 4) | 5, (0 << 6) | 0, len(seg) + 20, 0, 0, 64, 6, checksum, s, d)

    def enviar(self, segmento, dest_addr):
        """
        Envia segmento para dest_addr, onde dest_addr é um endereço IPv4
        (string no formato x.y.z.w).
        """
        next_hop = self._next_hop(dest_addr)

        self.enlace.enviar(self._make_header(segmento, self.meu_endereco, dest_addr) + segmento, next_hop)
