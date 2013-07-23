module Dissector
	APP_NAME = "dissector"
	VERSION = "0.0.1"
end

require 'ncursesw'
#require 'pcaprub'
require 'packetfu'

require 'dissector/colour_chooser'
require 'dissector/generate'
require 'dissector/listbox'
require 'dissector/packet'
require 'dissector/packets'
require 'dissector/structure'
require 'dissector/field'
require 'dissector/textbox'
require 'dissector/messagebox'
require 'dissector/hex'
require 'dissector/hex_window'
