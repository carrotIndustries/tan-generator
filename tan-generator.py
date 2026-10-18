from smartcard.CardConnectionObserver import ConsoleCardConnectionObserver
from smartcard.CardRequest import CardRequest
from smartcard.CardType import AnyCardType
from smartcard.Exceptions import CardRequestTimeoutException
from smartcard.sw.ErrorCheckingChain import ErrorCheckingChain
from smartcard.sw.ISO7816_4ErrorChecker import ISO7816_4ErrorChecker
from smartcard.sw.ISO7816_8ErrorChecker import ISO7816_8ErrorChecker
from smartcard.sw.ISO7816_9ErrorChecker import ISO7816_9ErrorChecker

import itertools

cardtype = AnyCardType()

cardrequest = CardRequest(timeout=10, cardType=cardtype)
cardservice = cardrequest.waitforcard()

errorchain = []
errorchain = [ErrorCheckingChain(errorchain, ISO7816_9ErrorChecker())]
errorchain = [ErrorCheckingChain(errorchain, ISO7816_8ErrorChecker())]
errorchain = [ErrorCheckingChain(errorchain, ISO7816_4ErrorChecker())]
cardservice.connection.setErrorCheckingChain(errorchain)

observer = ConsoleCardConnectionObserver()
cardservice.connection.addObserver(observer)

cardservice.connection.connect()

# SELECT FILE
cardservice.connection.transmit(list(bytes.fromhex('00 A4 04 0C 09 D2 76 00 00 25 54 44 01 00')))

#GET PROCESSING OPTIONS
cardservice.connection.transmit(list(bytes.fromhex('80 A8 00 00 02 83 00 00')))

#READ RECORD
response, sw1, sw2 = cardservice.connection.transmit(list(bytes.fromhex('00 B2 01 BC 00')))
kurz_blz = response[3]
kartennr = response[4:9]
print(f"Kurz-BLZ: {kurz_blz:02X}")
print("Kartennr:", "".join(f"{x:02X}" for x in kartennr))

#SEARCH RECORD IPB
response, sw1, sw2 = cardservice.connection.transmit(list(bytes.fromhex('00 A2 01 0F 09 04 00 CE 9F 56 00 00 00 FF 00')))

def parse_tlv(d) :
	i = 0
	r = {}
	while i < len(d) :
		tag = (d[i] << 8) | d[i+1]
		l = d[i+2]
		value = d[i+3:i+3+l]
		i += l + 3
		r[tag] = value
	return r

def dump_tlv(tlv) :
	for tag, value in tlv.items() :
		print(f"{tag:04X}: " + " ".join(f"{x:02X}" for x in value))

parsed = parse_tlv(response[3:])
bitmap = parsed[0x9f56]
dump_tlv(parsed)

print(f"Geographic Indicator: {parsed[0x9f55][0]:02X}")
print(f"Bitmap: " + " ".join(f"{x:02X}" for x in bitmap))

#SEARCH RECORD CDOL
response, sw1, sw2 = cardservice.connection.transmit(list(bytes.fromhex('00 A2 01 0F 08 04 00 CE 8C 00 00 00 FF 00')))
assert(response == list(bytes.fromhex('02 70 2E 8C 21 9F 02 06 9F 03 06 95 05 5F 2A 02 9A 03 9C 01 9F 37 04 9F 4C 08 9F 45 02 9F 33 03 9F 1A 02 9F 35 01 8D 09 91 10 8A 02 95 05 9F 37 04')))


# VERIFY
verify = list(bytes.fromhex('00 20 00 81 08 2C'))
verify.append(kurz_blz)
verify += kartennr
verify.append(0xff)
response, sw1, sw2 = cardservice.connection.transmit(verify)


# HASH
#start_code = '80 07 26 22'
start_code = input('Start code: ')
start_code = start_code.replace(' ', '')
assert(len(start_code) == 8)

mode = 'login'

if start_code.startswith("88") :
	mode = 'transfer'
	iban = input("IBAN: ")
	iban = iban.replace(" ", "")
	iban = iban[-10:]
	
	amount = input("Betrag: ")


pso_hash = [0x00, 0x2a, 0x90, 0xa0]

hash_data = [0x90, 0x00]
hash_data += [0x80, 0x81]

fmt_din = 0xe1
fmt_bcd = 0xe0

def build_fields(fields) :
	r = []
	for fmt, value in fields :
		r.append(fmt)
		if fmt == fmt_din :
			if type(value) is str :
				r += value.encode('ascii')
			else :
				assert(type(value) is bytes)
				r += value
		elif fmt == fmt_bcd :
			assert(len(value) % 2 == 0)
			r += bytes.fromhex(value)
		else :
			raise ValueError(f"unkown format {fmt}")
	r.append(0xb0 + len(fields))
	return r

fields_in = [
	(fmt_din, 'Start-Code:'),
	(fmt_bcd, start_code)
]

def pad_ff(s, l) :
	return s.encode('ascii').rjust(l, b'\xff')

if mode == 'transfer' :
	fields_in.append((fmt_din, 'IBAN'))
	fields_in.append((fmt_din, pad_ff(iban, 12)))
	fields_in.append((fmt_din, 'Betrag'))
	fields_in.append((fmt_din, pad_ff(amount, 12)))

fields = build_fields(fields_in)
hash_data.append(len(fields))
hash_data += fields

pso_hash.append(len(hash_data))
pso_hash += hash_data


pso_hash.append(0)
print("HASH")
response, sw1, sw2 = cardservice.connection.transmit(pso_hash)

hash_response = response[:29]

print(f"Hash: " + " ".join(f"{x:02X}" for x in hash_response))


# HASH (again)
response, sw1, sw2 = cardservice.connection.transmit(list(bytes.fromhex('00 2A 90 A0 04 90 00 80 00')))

# GENERATE AC

ac = list(bytes.fromhex('80 AE 00 00 00 00 2B'))
hash_pad = list(hash_response)
hash_pad += [0]*(45-len(hash_pad))
ac += hash_pad

response, sw1, sw2 = cardservice.connection.transmit(ac)
tan_data_in = list(itertools.chain.from_iterable(parse_tlv(response[2:-2]).values()))

bits_out = []
for mask, value in zip(bitmap, tan_data_in) :
	for i in reversed(range(8)) :
		if mask & (1<<i) :
			bits_out.append(value & (1<<i) != 0)

bits_shuf = bits_out[8:] + bits_out[:8]
tan = sum((1<<i) * x for i, x in enumerate(reversed(bits_shuf)))

print(f"TAN: {tan}")
