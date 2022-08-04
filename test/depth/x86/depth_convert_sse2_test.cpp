#ifdef ZIMG_X86

#include <cmath>
#include "common/cpuinfo.h"
#include "common/x86/cpuinfo_x86.h"
#include "common/pixel.h"
#include "depth/depth_convert.h"
#include "graphengine/filter.h"

#include "gtest/gtest.h"
#include "graphengine/filter_validation.h"

namespace {

void test_case_left_shift(const zimg::PixelFormat &pixel_in, const zimg::PixelFormat &pixel_out, const char *expected_sha1, double expected_snr)
{
	const unsigned w = 640;
	const unsigned h = 480;

	if (!zimg::query_x86_capabilities().sse2) {
		SUCCEED() << "sse2 not available, skipping";
		return;
	}

	auto filter_c = zimg::depth::create_left_shift(w, h, pixel_in, pixel_out, zimg::CPUClass::NONE);
	auto filter_sse2 = zimg::depth::create_left_shift(w, h, pixel_in, pixel_out, zimg::CPUClass::X86_SSE2);

	graphengine::FilterValidation(filter_sse2.get(), { w, h, zimg::pixel_size(pixel_in.type) })
		.set_reference_filter(filter_c.get(), expected_snr)
		.set_input_pixel_format({ pixel_in.depth, zimg::pixel_is_float(pixel_in.type), pixel_in.chroma })
		.set_output_pixel_format({ pixel_out.depth, zimg::pixel_is_float(pixel_out.type), pixel_out.chroma })
		.set_sha1(0, expected_sha1)
		.run();
}

void test_case_depth_convert(const zimg::PixelFormat &pixel_in, const zimg::PixelFormat &pixel_out, const char *expected_sha1, double expected_snr)
{
	const unsigned w = 640;
	const unsigned h = 480;

	if (!zimg::query_x86_capabilities().sse2) {
		SUCCEED() << "sse2 not available, skipping";
		return;
	}

	auto filter_c = zimg::depth::create_convert_to_float(w, h, pixel_in, pixel_out, zimg::CPUClass::NONE);
	auto filter_sse2 = zimg::depth::create_convert_to_float(w, h, pixel_in, pixel_out, zimg::CPUClass::X86_SSE2);

	graphengine::FilterValidation(filter_sse2.get(), { w, h, zimg::pixel_size(pixel_in.type) })
		.set_reference_filter(filter_c.get(), expected_snr)
		.set_input_pixel_format({ pixel_in.depth, zimg::pixel_is_float(pixel_in.type), pixel_in.chroma })
		.set_output_pixel_format({ pixel_out.depth, zimg::pixel_is_float(pixel_out.type), pixel_out.chroma })
		.set_sha1(0, expected_sha1)
		.run();
}

} // namespace


TEST(DepthConvertSSE2Test, test_left_shift_b2b)
{
	zimg::PixelFormat pixel_in{ zimg::PixelType::BYTE, 4 };
	zimg::PixelFormat pixel_out{ zimg::PixelType::BYTE, 8 };

	const char *expected_sha1 = "09f66fc9d2221b4fad52b3e18b9b31585ebd2b61";

	test_case_left_shift(pixel_in, pixel_out, expected_sha1, INFINITY);
}

TEST(DepthConvertSSE2Test, test_left_shift_b2w)
{
	zimg::PixelFormat pixel_in{ zimg::PixelType::BYTE, 8 };
	zimg::PixelFormat pixel_out{ zimg::PixelType::WORD, 16 };

	const char *expected_sha1 = "d5794ead078fee72fd10fc396aef511c96f8279c";

	test_case_left_shift(pixel_in, pixel_out, expected_sha1, INFINITY);
}

TEST(DepthConvertSSE2Test, test_left_shift_w2b)
{
	zimg::PixelFormat pixel_in{ zimg::PixelType::WORD, 4 };
	zimg::PixelFormat pixel_out{ zimg::PixelType::BYTE, 8 };

	const char *expected_sha1 = "09f66fc9d2221b4fad52b3e18b9b31585ebd2b61";

	test_case_left_shift(pixel_in, pixel_out, expected_sha1, INFINITY);
}

TEST(DepthConvertSSE2Test, test_left_shift_w2w)
{
	zimg::PixelFormat pixel_in{ zimg::PixelType::WORD, 10 };
	zimg::PixelFormat pixel_out{ zimg::PixelType::WORD, 16 };

	const char *expected_sha1 = "1fa20cfbaa8c2de073d5a9569e474c164c4d3ec6";

	test_case_left_shift(pixel_in, pixel_out, expected_sha1, INFINITY);
}

TEST(DepthConvertSSE2Test, test_depth_convert_b2f)
{
	zimg::PixelFormat pixel_in{ zimg::PixelType::BYTE, 8, true };
	zimg::PixelFormat pixel_out{ zimg::PixelType::FLOAT };

	const char *expected_sha1 = "20c77820ff7d4443a0de7991218e2f8eee551e8d";

	test_case_depth_convert(pixel_in, pixel_out, expected_sha1, INFINITY);
}

TEST(DepthConvertSSE2Test, test_depth_convert_w2f)
{
	zimg::PixelFormat pixel_in{ zimg::PixelType::WORD, 16, true };
	zimg::PixelFormat pixel_out{ zimg::PixelType::FLOAT };

	const char *expected_sha1 = "7ad2bc4ba1be92699ec22f489ae93a8b0dc89821";

	test_case_depth_convert(pixel_in, pixel_out, expected_sha1, INFINITY);
}

#endif // ZIMG_X86
