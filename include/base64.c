/*
Writen By:
Jon Moroney and Edoardo S. Biagioni
Because for some reason it's had to find a simple, free license, base64 encode function in the year 2015. Go figure.

License:
The MIT License (MIT)

Copyright (c) 2015 Jon Moroney and Edoardo S. Biagioni

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.


What it does:
Take in an input buffer and encode to a base64 ascii string
The input variable 'input_length' is the length of the input buffer in bytes
Return value is output_buffer_length on sucess and -1 on failure.
The reason for having output_buffer_length as both an input and an output is twofold
1) it allows for two different styles of programming
2) it allows for error checking

Author's Note:
This process could (and maybe should) be refered to as 'arming ascii' as base64 encoding is also know as ascii armor
See https://tools.ietf.org/html/rfc4880 for more information about 'ascii armor' and possibly other ascii weaponization techniques
*/
#include <string.h>

int base64_encode(char* input_buffer, int input_length, char* output_buffer, int output_buffer_length, char * lookup_string, int lookup_string_length)
{
  if (output_buffer_length<(((input_length*4)/3) + 3))
  {
    return -1;
  }
  //See https://en.wikipedia.org/wiki/Base64 for an explination on the lookup table
  char base64_lookup[65] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

  //Validate lookup_string and use it.
  if (lookup_string_length==64)
  {
    strcpy(base64_lookup, lookup_string);
  }

  int i, index = 0;
  int character1, character2, character3 = 0;
  int temp_bits1, temp_bits2, temp_bits3, temp_bits4 = 0;

  for (i = 0; i<input_length; i+=3)
  {
    /* split 3 characters into 4 groups of at most 6 bits each */
    character1 = (input_buffer[i]) & 0xff;
    if (i + 1 < input_length)
    {
      character2 = (input_buffer[i+1]) & 0xff;
    }
    if (i + 2 < input_length)
    {
      character3 = (input_buffer[i+2]) & 0xff;
    }
    temp_bits1 = (character1>>2) & 0x3f;
    temp_bits2 = ((character1<<4) | (character2>>4)) & 0x3f;
    temp_bits3 = ((character2<<2) | (character3>>6)) & 0x3f;
    temp_bits4 = character3 & 0x3f;

    output_buffer[index++] = base64_lookup[temp_bits1];
    output_buffer[index++] = base64_lookup[temp_bits2];
    if (i + 1 < input_length)
    {
      output_buffer[index++] = base64_lookup[temp_bits3];
    }
    else
    {
      output_buffer[index++] = '=';
    }
    if (i + 2 < input_length)
    {
      output_buffer[index++] = base64_lookup[temp_bits4];
    }
    else
    {
      output_buffer[index++] = '=';
    }
  }
  output_buffer[index] = '\0';
  output_buffer_length = index;
  return index;
}

int base64_default_encode(char* input_buffer, int input_length, char* output_buffer, int output_buffer_length)
{
  int index = 0;
  index = base64_encode(input_buffer, input_length, output_buffer, output_buffer_length, NULL, 0);
  return index;
}
