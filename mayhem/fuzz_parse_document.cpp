#include <stdint.h>
#include <stdio.h>
#include <climits>

#include <fuzzer/FuzzedDataProvider.h>
#include "json.h"

extern "C" unsigned zimg_select_buffer_mask(unsigned count);

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    std::string document = provider.ConsumeRandomLengthString();
    try
    {
        json::parse_document(document);
    }
    catch (json::JsonError)
    {
    }
    return 0;
}
