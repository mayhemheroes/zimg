#ifdef ZIMG_X86

#include <cmath>
#include "common/cpuinfo.h"
#include "common/pixel.h"
#include "common/x86/cpuinfo_x86.h"
#include "depth/depth_convert.h"
#include "graphengine/filter.h"

#include "gtest/gtest.h"
#include "graphengine/filter_validation.h"

namespace {

void test_case(zimg::PixelType pixel_in, zimg::PixelType pixel_out, const char *expected_sha1, double expected_snr)
{
	const unsigned w = 640;
	const unsigned h = 480;

	if (!zimg::query_x86_capabilities().f16c) {
		SUCCEED() << "f16c not available, skipping";
		return;
	}

	auto filter_c = zimg::depth::create_convert_to_float(w, h, pixel_in, pixel_out, zimg::CPUClass::NONE);
	auto filter_sse2 = zimg::depth::create_convert_to_float(w, h, pixel_in, pixel_out, zimg::CPUClass::X86_SSE2);

	graphengine::FilterValidation(filter_sse2.get(), { w, h, zimg::pixel_size(pixel_in) })
		.set_reference_filter(filter_c.get(), expected_snr)
		.set_input_pixel_format({ zimg::pixel_depth(pixel_in), zimg::pixel_is_float(pixel_in), false })
		.set_output_pixel_format({ zimg::pixel_depth(pixel_out), zimg::pixel_is_float(pixel_out), false })
		.set_sha1(0, expected_sha1)
		.run();
}

} // namespace


TEST(F16CSSE2Test, test_half_to_float)
{
	const char *expected_sha1 = "68442b2c5704fd2792d92b15fa2e259a51c601dc";

	test_case(zimg::PixelType::HALF, zimg::PixelType::FLOAT, expected_sha1, INFINITY);
}

TEST(F16CSSE2Test, test_float_to_half)
{
	const char *expected_sha1 = "4184caae2bd2a3f54722cba1d561cc8720b117ce";

	// The SSE2 approximation does not implement correct rounding.
	test_case(zimg::PixelType::FLOAT, zimg::PixelType::HALF, expected_sha1, 90.0);
}

#endif // ZIMG_X86
