#pragma once

#ifndef ZIMG_GRAPH_GRAPHBUILDER_H_
#define ZIMG_GRAPH_GRAPHBUILDER_H_

#include <array>
#include <memory>
#include <utility>
#include <vector>
#include "colorspace/colorspace.h"
#include "graphengine/types.h"

namespace graphengine {
class Filter;
class Graph;
class SubGraph;
}


namespace zimg {

enum class CPUClass;
enum class PixelType;

namespace depth {
enum class DitherType;
struct DepthConversion;
}

namespace resize {
class Filter;
struct ResizeConversion;
}

namespace unresize {
struct UnresizeConversion;
}


namespace graph {

class FilterGraph2;

/**
 * Observer interface for debugging filter instantiation.
 */
class FilterObserver {
public:
	virtual ~FilterObserver() = default;

	virtual void subrectangle(unsigned left, unsigned top, unsigned width, unsigned height, int plane) {}

	virtual void yuv_to_grey() {}
	virtual void grey_to_yuv() {}
	virtual void grey_to_rgb() {}

	virtual void premultiply() {}
	virtual void unpremultiply() {}
	virtual void add_opaque() {}
	virtual void discard_alpha() {}

	virtual void colorspace(const colorspace::ColorspaceConversion &conv) {}
	virtual void depth(const depth::DepthConversion &conv, int plane) {}
	virtual void resize(const resize::ResizeConversion &conv, int plane) {}
	virtual void unresize(const unresize::UnresizeConversion &conv, int plane) {}
};


/**
 * Holds a subgraph that can be inserted into an actual graph instance.
 */
class SubGraph {
private:
	std::vector<std::unique_ptr<graphengine::Filter>> m_filters;
	std::unique_ptr<graphengine::SubGraph> m_subgraph;
	graphengine::node_id m_source_ids[4];
	graphengine::node_id m_sink_ids[4];
public:
	SubGraph();

	SubGraph(SubGraph &&other) noexcept;

	~SubGraph();

	SubGraph &operator=(SubGraph &&other) noexcept;

	graphengine::node_dep_desc source_plane_0() const { return{ m_source_ids[0], 0 }; }
	graphengine::node_dep_desc source_plane_1() const { return{ m_source_ids[1], 0 }; }
	graphengine::node_dep_desc source_plane_2() const { return{ m_source_ids[2], 0 }; }
	graphengine::node_dep_desc source_plane_3() const { return{ m_source_ids[3], 0 }; }

	const graphengine::Filter *save_filter(std::unique_ptr<graphengine::Filter> filter);

	graphengine::node_id add_transform(const graphengine::Filter *filter, const graphengine::node_dep_desc deps[]);

	void set_sink(unsigned num_planes, const graphengine::node_dep_desc deps[]);

	std::array<graphengine::node_dep_desc, 4> connect(graphengine::Graph *graph, const graphengine::node_dep_desc source_deps[4]) const;

	std::vector<std::unique_ptr<graphengine::Filter>> release_filters();

	std::shared_ptr<void> release_filters_opaque();
};


/**
 * Models a filter graph with one source node and one sink node.
 */
class GraphBuilder {
	struct internal_state;
public:
	// Interpretation of the three color channels.
	enum class ColorFamily {
		GREY,
		RGB,
		YUV,
	};

	// Whether an alpha channel is present and whether the color channels have
	// been premultiplied with the alpha channel.
	enum class AlphaType {
		NONE,
		STRAIGHT,
		PREMULTIPLIED,
	};

	// Whether the image is a frame or a field.
	enum class FieldParity {
		PROGRESSIVE,
		TOP,
		BOTTOM,
	};

	// For horizontally subsampled YUV.
	enum class ChromaLocationW {
		LEFT,
		CENTER,
	};

	// For vertically subsampled YUV.
	enum class ChromaLocationH {
		CENTER,
		TOP,
		BOTTOM,
	};

	// Canonical state.
	struct state {
		unsigned width;
		unsigned height;
		PixelType type;
		unsigned subsample_w;
		unsigned subsample_h;

		ColorFamily color;
		colorspace::ColorspaceDefinition colorspace;

		unsigned depth;
		bool fullrange;

		FieldParity parity;
		ChromaLocationW chroma_location_w;
		ChromaLocationH chroma_location_h;

		double active_left;
		double active_top;
		double active_width;
		double active_height;

		AlphaType alpha;
	};

	// Filter instantiation parameters.
	struct params {
		const resize::Filter *filter;
		const resize::Filter *filter_uv;
		bool unresize;
		depth::DitherType dither_type;
		double peak_luminance;
		bool approximate_gamma;
		bool scene_referred;
		CPUClass cpu;

		params() noexcept;
	};
private:
	class impl;

	std::unique_ptr<impl> m_impl;

	impl *get_impl() noexcept { return m_impl.get(); }
public:
	/**
	 * Default construct GraphBuilder, creating an empty graph.
	 */
	GraphBuilder();

	/**
	 * Destory builder.
	 */
	~GraphBuilder();

	/**
	 * Set image format of the source node in the graph.
	 *
	 * A graph must have exactly one source node. GraphBuilder::set_source
	 * must be the first function called. Since a graph can have only one
	 * output node, the source format also becomes the current working format.
	 *
	 * @param source image format
	 * @return reference to self
	 */
	GraphBuilder &set_source(const state &source);

	/**
	 * Convert current graph node to target format.
	 *
	 * GraphBuilder::connect may be called multiple times to implement custom
	 * format negotiation logic. After each call, the graph's current working
	 * format is updated to the target format.
	 *
	 * For debugging purposes, the observer is called with the details of each
	 * internal operation.
	 *
	 * @param target image format
	 * @param params filter instantiation parameters
	 * @params observer observer
	 */
	GraphBuilder &connect(const state &target, const params *params, FilterObserver *observer = nullptr);

	/**
	 * Finalize and return a partial graph.
	 *
	 * The partial graph can be used to apply the modeled transformation to nodes
	 * already present in another graph.
	 *
	 * @return graph
	 */
	SubGraph build_subgraph();

	/**
	 * Finalize and return a complete filter graph.
	 *
	 * Returns a graph with the output node set to the current format.
	 *
	 * @return graph
	 */
	std::unique_ptr<FilterGraph> build_graph();
};

} // namespace graph
} // namespace zimg

#endif // ZIMG_GRAPH_GRAPHBUILDER_H_
