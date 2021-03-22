WCH340G
=======

The W.CH340G is a different die from the WCH340. It doesn't appear
to have an EEPROM, but has twice the amount of ROM (2k words instead
of 1k words).

Strings in the ROM (starting at word 0x5A3) indicate support for
"Print ", "Serial", "MIDI  "; likely indicating a shared ROM with
other WCH chips.

Credits
-------

 - SEM image by Felix Domke (@tmbinc)
 - Bit extractions by Chris Gerlinsky (@akacastor)
 - Making sense out of the bits by Ryan Ringo (@ringoware)
