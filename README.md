TAN Generator
======

This is an attempt at implementing a software TAN generator for the [ChipTAN](https://en.wikipedia.org/wiki/Transaction_authentication_number#ChipTAN_/_Sm@rt-TAN_/_CardTAN) method that's used by some German banks for authorizing transfers and login for online banking. ChipTAN usually involves a special-purpose TAN generator device that receives the transaction details either by flicker code, QR code or manual input on a keypad and interfaces with the banking card to generate a TAN to authorize a given transaction.

Apart from interfacing to the card, the TAN generator shows the transaction details on a separate device that's not susceptible to malware that could obscure the true recipient of a transaction.

# Motivation

I sometimes wanted to transfer money using SEPA, but didn't have a TAN generator with me. It then occurred to me that my laptop has a smart card reader builtin that could be used to interface with the banking card.

# Security considerations

Compared to a physical TAN generator, a software-only TAN generator results in reduced security compared to a separate device since highly targeted malware could obscure the true recipient of a transaction or use an existing online banking session and access to the card to authorize arbitrary transfers.

# Research

To implement a software-based TAN generator, I needed to know in which way to send the transaction details to the card and how to construct the TAN from its response. Luckily, people at CCC FFM [already figured that out](https://wiki.ccc-ffm.de/projekte:tangenerator:start)! Without this, I probably wouldn't have started the project in the first place.

To confirm that this is what my TAN generator actually sends to the card, I built a [breakout board](https://github.com/carrotIndustries/smartcard-breakout/#smart-card-breakout) and used a cheap FX2-based logic analyzer and pulseview to capture and partially decode the traffic. The correct settings for the UART decoder are

 - 41666 Baud
 - Even parity

The card and terminal switch baud rates in between, but everything relevant happens at the above settings. Getting the decoded data out of pulseview is a bit non-intuitive: The All of the "Save as" options only seems to save the raw logic data, not the output of the UART decoder. Instead, one has to right click the decoded UART data and select "Export all annotations for this row, starting here". This then results in a file that looks roughly like so:
```
6073329-6073378 UART: RX: Start bit
6073377-6073762 UART: RX: 00
6073761-6073810 UART: RX: Parity bit
6073809-6073858 UART: RX: Stop bit
6073916-6073965 UART: RX: Start bit
6073964-6074349 UART: RX: C1
6074348-6074397 UART: RX: Parity bit
6074396-6074445 UART: RX: Stop bit
6074502-6074551 UART: RX: Start bit
6074550-6074935 UART: RX: 01
```

A [hacky python script](parse-sigrok.py) then turns this into something more readable and also parses the T=1 headers to turn the continuous stream of bytes into individual APDUs.

For the manual ChipTAN process, my findings matched the analysis on the CCC FFM Wiki pretty much exactly.

# Implementation

Now that I made sense of the communication between TAN generator and card, I could start implementing it myself. To talk to the card, I'm using my laptop's integrated smart card reader and [pyscard](https://github.com/LudovicRousseau/pyscard). One side note about the [PCSC lite](https://pcsclite.apdu.fr/) project: If you think the API looks surprisingly [win32-esque](https://pcsclite.apdu.fr/api/group__API.html#ga4e515829752e0a8dbc4d630696a8d6a5)
 with its hungarian notation for function arguments, you're correct. It's an API-compatible reimplementation of the Windows [SCard API](https://learn.microsoft.com/en-us/windows/win32/api/winscard/nf-winscard-scardconnecta)

Some hacking later, we now have a proof of concept quality [soft tan generator](tan-generator.py) that I was able to use to

 - Login to my online banking
 - Authorize domestic SEPA transfers

# Future work

Standing orders or international transfers are indicated by a different start code prefix and may require additional user input. This data has to be added to what's sent for hashing to the card.
 
# What didn't work

## chipTAN QR

I first tried to implement the method where the transaction information gets transferred to the TAN generator using a QR code. However, there were some pieces in the protocol around the "AMS" that's embedded in the QR code that I couldn't figure out based on protocol dumps and the snippets of documentation I could find.

## NFC

Using the [ifdnlnfc](https://github.com/jurajsarinay/ifdnlnfc) project, I managed to send APDUs to the card using the NFC reader built into my laptop. However, the card rejected the initial SELECT FILE APDU:
```
> 00 A4 04 0C 09 D2 76 00 00 25 54 44 01 00
< 69 85 : Command not allowed. Conditions of use not satisfied.
```

While it'd have been really cool to authorize transactions just by placing the card on the touchpad of my laptop which is where the NFC antenna sits, it's probably for the better in terms of security that TAN generation is only allowed for wired connection.