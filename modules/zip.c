/*
Copyright (c) 2014. The YARA Authors. All Rights Reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
this list of conditions and the following disclaimer in the documentation and/or
other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors
may be used to endorse or promote products derived from this software without
specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include <yara/modules.h>
#include <yara/miniz.h>

#define MODULE_NAME zip

define_function(unpack)
{
    YR_SCAN_CONTEXT* module_context = scan_context();
    char* file_name = string_argument(1);
    char* search_string = string_argument(2);
    if(module_context != NULL)
    {
      YR_MEMORY_BLOCK* block;

      block = first_memory_block(module_context);
      uint8_t *buffer = (uint8_t*)block->fetch_data(block);
      mz_zip_archive zip;
      mz_zip_archive_file_stat stat;
      size_t size = 0;
      memset(&zip, 0, sizeof(zip));

      if(!mz_zip_reader_init_mem(&zip, buffer, module_context->file_size, 0))
      { //Error: Could not init File from Memory
        mz_zip_reader_end(&zip);
        return_integer(YR_UNDEFINED);
      }

      int file_index = mz_zip_reader_locate_file(&zip, file_name, 0, 0);
      if (file_index < 0)
      { //Error: Could not find File
        mz_zip_reader_end(&zip);
        return_integer(YR_UNDEFINED);
      }

      if (!mz_zip_reader_file_stat(&zip, file_index, &stat))
      { //Error: Could not read Status
        mz_zip_reader_end(&zip);
        return_integer(YR_UNDEFINED);
      }

      if (stat.m_uncomp_size<100*1024*1024)
      {
        void *p = mz_zip_reader_extract_to_heap(&zip, file_index, &size, 0);
        if (!p) //Error: Could not read File to Heap
        {
          mz_zip_reader_end(&zip);
          return_integer(YR_UNDEFINED);
        }
        else
        {
          char *result = strstr(p, search_string);
          if(result != NULL)
            return_integer((void*)result-p);
        }
      }
    }
    return_integer(YR_UNDEFINED);
}

begin_declarations;
  declare_function("has_string", "ss", "i", unpack);
end_declarations;

int module_initialize(
    YR_MODULE* module)
{
  return ERROR_SUCCESS;
}

int module_finalize(
    YR_MODULE* module)
{
  return ERROR_SUCCESS;
}

int module_load(
    YR_SCAN_CONTEXT* context,
    YR_OBJECT* module_object,
    void* module_data,
    size_t module_data_size)
{
  return ERROR_SUCCESS;
}

int module_unload(
    YR_OBJECT* module_object)
{
  return ERROR_SUCCESS;
}

#undef MODULE_NAME
