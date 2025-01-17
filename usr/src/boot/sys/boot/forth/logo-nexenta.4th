\ Copyright (c) 2003 Scott Long <scottl@FreeBSD.org>
\ Copyright (c) 2003 Aleksander Fafula <alex@fafula.com>
\ Copyright (c) 2006-2015 Devin Teske <dteske@FreeBSD.org>
\ All rights reserved.
\ Copyright 2019 OmniOS Community Edition (OmniOSce) Association.
\ All rights reserved.
\ Copyright 2020 Tintri by DDN. All rights reserved.
\
\ Redistribution and use in source and binary forms, with or without
\ modification, are permitted provided that the following conditions
\ are met:
\ 1. Redistributions of source code must retain the above copyright
\    notice, this list of conditions and the following disclaimer.
\ 2. Redistributions in binary form must reproduce the above copyright
\    notice, this list of conditions and the following disclaimer in the
\    documentation and/or other materials provided with the distribution.
\
\ THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
\ ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
\ IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
\ ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
\ FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
\ DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
\ OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
\ HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
\ LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
\ OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
\ SUCH DAMAGE.
\

variable PNGLogo
0 PNGLogo !

51 logoX !
2 logoY !

: logo+ ( x y c-addr/u -- x y' )
	2swap 2dup at-xy 2swap	\ position the cursor
	[char] @ escc!		\ replace @ with Esc
	type			\ print to the screen
	1+			\ increase y for next time we're called
;

: menupos ( y -- )	\ Adjust menu position
	dup 14 +	\ timeout is 14 lines below menu start
	n2s s" loader_menu_timeout_y" setenv
	n2s s" loader_menu_y" setenv
;

: nexenta     0  30  20   0   0	s" /boot/nexenta.png" fb-putimage ;

: logo ( x y -- )
	framebuffer? if
		s" loader_font" set_font
		clear
		at-bl
		nexenta if
			1 PNGLogo !
			13 menupos
			2drop
			exit
		then
	then

	0 PNGLogo !
	11 menupos
	at-bl

	2drop
;

