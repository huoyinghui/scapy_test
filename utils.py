"""
随机dns数据包：


概念:
1.x0-x12: 共13个维度的数据, 组合不同的dns数据包
2.xmax_map: 是每个维度的上限索引


测试效果:
{'x0': 1, 'x1': 3, 'x2': 1, 'x3': 1, 'x4': 102, 'x5': 102, 'x6': 102, 'x7': 102, 'x8': 4,
'x9': 103, 'x10': 102, 'x11': 103, 'x12': 102}

随机坐标: (1, 3, 0, 0, 0, 2, 100, 102, 4, 76, 12, 57, 0)
.
Sent 1 packets.
send query:b'E\x00\x00\x80\x00\x01\x00\x00@\x11|\xee\x11\x00\x00\x01\xc0\xa8+\xd5\x8c\xe7\x005\x00l
`2\x00\x00\xf8\x00\x00\x00\xff\xff^\x17}\x92?U=p75(aQ0$G)OyM*3koskYN$XG#5-fJ$XiY=AXs9mSvomDdxX^S67J%jxd1+
!0G\x03bcg\x03nej\x00\x00\xde\x00\xff\x001l\x95?la\x1d\xf8\x00\x00'

"""
import logging
from scapy.all import *


# 配置日志文件和日志级别
logging.basicConfig(
    filename='dns_log.txt',
    level=logging.DEBUG,
    format='%(asctime)s:%(funcName)15s:%(lineno)5s%(levelname)8s:%(name)10s:%(message)s',
    datefmt='%Y/%m/%d %I:%M:%S'
)

logger = logging.getLogger('dns_log')


def get_ip(ifname):
    local_ip = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(local_ip.fileno(), 0x8915, struct.pack('256s', bytes(ifname[:15], 'utf-8')))[20:24])


def make_domain_name():
    seed = '1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXY#!@$%^&*()_+=-'
    sa = []
    for i in range(100):
        sa.append(random.choice(seed))
    host = ''.join(sa)
    TLDstring = RandString(RandNum(2, 3))
    tld = TLDstring.lower()
    SLDstring = RandString(RandNum(3, 6))
    sld = SLDstring.lower()
    name = host + "." + sld.decode() + "." + tld.decode()
    return name


def make_random(start=0, end=65535):
    res = []
    for i in range(100):
        if i > 65535:
            logger.error("make_random err:{}".format(i))
            raise ("i:{} > 65535".format(i))
        res.append(random.randint(start, end))
    return res


def make_random(start=0, end=65535):
    res = []
    for i in range(100):
        res.append(random.randint(start, end))
    return res


def make_dns_query(
    qr_ele=0,
    opcode_ele=0,
    tc_ele=0,
    rd_ele=0,
    qd_ele=1,
    an_ele=0,
    ns_ele=0,
    ar_ele=0,
    qclass_ele=1,
    ar_type_ele=41,
    ar_ttl_ele=60,
    ar_rclass_ele=512,
    ar_rdlen_ele=0
):

    logger.debug("make_dns_query:{}".format((qr_ele, opcode_ele, tc_ele, rd_ele, qd_ele, an_ele,
                                             ns_ele, ar_ele, qclass_ele, ar_type_ele, ar_ttl_ele, ar_rclass_ele, ar_rdlen_ele)))
    dns_query = DNS(id=0, qr=qr_ele, opcode=opcode_ele, tc=tc_ele, rd=rd_ele, qdcount=qd_ele, ancount=an_ele,
                    nscount=ns_ele, arcount=ar_ele)
    qtype_list = list(range(0, 255))
    query_type = random.sample(qtype_list, 1)
    domain_name = make_domain_name()
    dns_query.qd = DNSQR(
        qname=domain_name, qtype=query_type, qclass=qclass_ele)
    dns_query.ar = DNSRR(type=ar_type_ele, ttl=ar_ttl_ele,
                         rclass=ar_rclass_ele, rdlen=ar_rdlen_ele)
    global ip
    global udp
    query = ip / udp / dns_query
    return query


def check(*index_list):
    for index, x in enumerate(index_list):
        key = "x{}".format(index)
        xmax = xmax_map.get(key, -1)
        if x > xmax:
            logging.info(
                "{} index out of range, you input {}, max value is {}".format(key, x, xmax))
            return False
    return True


def index_data_table(x0=0, x1=0, x2=0, x3=0, x4=0, x5=0, x6=0, x7=0, x8=0, x9=0, x10=0, x11=0, x12=0):
    index_list = (x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12)
    if not check(*index_list):
        logger.error("index err: {}".format(index_list))
        return None
    qr_ele = qr_list[x0]
    opcode_ele = opcode_list[x1]
    tc_ele = tc_list[x2]
    rd_ele = rd_list[x3]
    qd_ele = qdcount_list[x4]
    an_ele = ancount_list[x5]
    ns_ele = nscount_list[x6]
    ar_ele = arcount_list[x7]
    qclass_ele = qclass_list[x8]
    ar_type_ele = ar_type_list[x9]
    ar_ttl_ele = ar_ttl_list[x10]
    ar_rclass_ele = ar_rclass_list[x11]
    ar_rdlen_ele = ar_rdlen_list[x12]
    query = make_dns_query(
        qr_ele=qr_ele,
        opcode_ele=opcode_ele, tc_ele=tc_ele, rd_ele=rd_ele,
        qd_ele=qd_ele, an_ele=an_ele, ns_ele=ns_ele, ar_ele=ar_ele,
        qclass_ele=qclass_ele, ar_type_ele=ar_type_ele,
        ar_ttl_ele=ar_ttl_ele, ar_rclass_ele=ar_rclass_ele,
        ar_rdlen_ele=ar_rdlen_ele,
    )
    send(query)
    logging.info("index:{} :send query:{}".format(index_list, query))


# client_server = get_ip('knil')
client_server = "127.0.0.1"
dns_server = '192.168.43.213'
dns_dport = 53

qr_list = range(0, 2)
opcode_list = [0, 1, 2, 15]
tc_list = range(0, 2)
rd_list = range(0, 2)

qdcount_list = [0, 1, 65535] + make_random()
ancount_list = [0, 1, 65535] + make_random()
nscount_list = [0, 1, 65535] + make_random()
arcount_list = [0, 1, 65535] + make_random()
logger.info("qdcount_list:{}".format(qdcount_list))
logger.info("ancount_list:{}".format(ancount_list))
logger.info("nscount_list:{}".format(nscount_list))
logger.info("arcount_list:{}".format(arcount_list))

qclass_list = [1, 2, 3, 4, 255]

ar_type_list = [0, 1, 30000, 65535] + make_random()
ar_ttl_list = [0, 1, 0xFFFFFFFF] + make_random(0, 0xFFFFFFFF)
ar_rclass_list = [0, 1500, 4096, 65535] + make_random()
ar_rdlen_list = [0, 31900, 65535] + make_random()
logger.info("ar_type_list:{}".format(ar_type_list))
logger.info("ar_ttl_list:{}".format(ar_ttl_list))
logger.info("ar_rclass_list:{}".format(ar_rclass_list))
logger.info("ar_rdlen_list:{}".format(ar_rdlen_list))

ip = IP(dst=dns_server, src=client_server)
udp = UDP(sport=RandShort(), dport=dns_dport)
logger.info("ip:{}".format(ip))
logger.info("udp:{}".format(udp))

# xmax_map 记录最大index
# {'x0': 1, 'x1': 3, 'x2': 1, 'x3': 1, 'x4': 102, 'x5': 102, 'x6': 102,
# 'x7': 102, 'x8': 4, 'x9': 103, 'x10': 102, 'x11': 103, 'x12': 102}
xmax_map = {
    "x0": len(qr_list) - 1,
    "x1": len(opcode_list) - 1,
    "x2": len(tc_list) - 1,
    "x3": len(rd_list) - 1,

    "x4": len(qdcount_list) - 1,
    "x5": len(ancount_list) - 1,
    "x6": len(nscount_list) - 1,
    "x7": len(arcount_list) - 1,

    "x8": len(qclass_list) - 1,

    "x9": len(ar_type_list) - 1,
    "x10": len(ar_ttl_list) - 1,
    "x11": len(ar_rclass_list) - 1,
    "x12": len(ar_rdlen_list) - 1,
}

logger.info("xmax_map:{}".format(xmax_map))


def random_index():
    """
    随机生成合法的坐标
    :return:
    """
    x = (
        random.randint(0, xmax_map["x0"]),
        random.randint(0, xmax_map["x1"]),
        random.randint(0, xmax_map["x2"]),
        random.randint(0, xmax_map["x3"]),
        random.randint(0, xmax_map["x4"]),
        random.randint(0, xmax_map["x5"]),
        random.randint(0, xmax_map["x6"]),
        random.randint(0, xmax_map["x7"]),
        random.randint(0, xmax_map["x8"]),
        random.randint(0, xmax_map["x9"]),
        random.randint(0, xmax_map["x10"]),
        random.randint(0, xmax_map["x11"]),
        random.randint(0, xmax_map["x12"]),
    )
    logger.info("index:".format(x))
    return x


def random_dns_send():
    x = random_index()
    index_data_table(*x)


def create_index():
    """
    生成测试随机组合
    :return:
    """
    for x0 in range(xmax_map.get('x0', 0)):
        for x1 in range(xmax_map.get('x1', 0)):
            for x2 in range(xmax_map.get('x2', 0)):
                for x3 in range(xmax_map.get('x3', 0)):
                    for x4 in range(xmax_map.get('x4', 0)):
                        for x5 in range(xmax_map.get('x5', 0)):
                            for x6 in range(xmax_map.get('x6', 0)):
                                for x7 in range(xmax_map.get('x7', 0)):
                                    for x8 in range(xmax_map.get('x8', 0)):
                                        for x9 in range(xmax_map.get('x9', 0)):
                                            for x10 in range(xmax_map.get('x10', 0)):
                                                for x11 in range(xmax_map.get('x11', 0)):
                                                    for x12 in range(xmax_map.get('x12', 0)):
                                                        yield x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12


def save_dns_index():
    """
    生成dns，坐标数据表，写入到数据库
    1.x1, x2, x3, ...x12
    2.x1, x2, x3, ...x12
    3.x1, x2, x3, ...x12
    ...
    n.x1, x2, x3, ...x12
    :return:
    """
    with open("a.txt", "a+") as f:
        for index in create_index():
            f.writelines("{}\n".format(index))
    return


def main():
    # try:
    for index in create_index():
        # logger.debug("{}".format(index))
        index_data_table(*index)
    # except Exception as e:
    #     print("{}".format(e))


if __name__ == '__main__':
    main()
