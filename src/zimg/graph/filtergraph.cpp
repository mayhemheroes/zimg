#include <algorithm>
#include <climits>
#include "common/except.h"
#include "common/zassert.h"
#include "graphengine/graph.h"
#include "graphengine/types.h"
#include "filtergraph.h"
#include "graphengine_except.h"

namespace zimg {
namespace graph {

FilterGraph::FilterGraph(std::unique_ptr<graphengine::Graph> graph, std::shared_ptr<void> instance_data, graphengine::node_id source_id, graphengine::node_id sink_id) :
	m_graph{ std::move(graph) },
	m_instance_data{ std::move(instance_data) },
	m_source_id{ source_id },
	m_sink_id{ sink_id },
	m_requires_64b{},
	m_source_greyalpha{},
	m_sink_greyalpha{}
{}

FilterGraph::~FilterGraph() = default;

size_t FilterGraph::get_tmp_size() const try
{
	return m_graph->get_tmp_size();
} catch (const graphengine::Exception &e) {
	rethrow_graphengine_exception(e);
}

unsigned FilterGraph::get_input_buffering() const try
{
	graphengine::Graph::BufferingRequirement buffering = m_graph->get_buffering_requirement();
	auto it = std::find_if(buffering.begin(), buffering.end(), [=](const auto &entry) { return entry.id == m_source_id; });
	zassert(it != buffering.end(), "invalid node id");
	return std::min(it->mask, UINT_MAX - 1) + 1;
} catch (const graphengine::Exception &e) {
	rethrow_graphengine_exception(e);
}

unsigned FilterGraph::get_output_buffering() const try
{
	graphengine::Graph::BufferingRequirement buffering = m_graph->get_buffering_requirement();
	auto it = std::find_if(buffering.begin(), buffering.end(), [=](const auto &entry) { return entry.id == m_sink_id; });
	zassert(it != buffering.end(), "invalid node id");
	return std::min(it->mask, UINT_MAX - 1) + 1;
} catch (const graphengine::Exception &e) {
	rethrow_graphengine_exception(e);
}

unsigned FilterGraph::get_tile_width() const try
{
	return graphengine::GraphImpl::from(m_graph.get())->get_tile_width(false);
} catch (const graphengine::Exception &e) {
	rethrow_graphengine_exception(e);
}

void FilterGraph::set_tile_width(unsigned tile_width)
{
	graphengine::GraphImpl::from(m_graph.get())->set_tile_width(tile_width);
}

void FilterGraph::process(const std::array<graphengine::BufferDescriptor, 4> &src, const std::array<graphengine::BufferDescriptor, 4> &dst, void *tmp, callback_type unpack_cb, void *unpack_user, callback_type pack_cb, void *pack_user) const
{
	graphengine::Graph::Endpoint endpoints[] = {
		{ m_source_id, src.data(), { unpack_cb, unpack_user } },
		{ m_sink_id, dst.data(), { pack_cb, pack_user } },
	};

	graphengine::BufferDescriptor src_reorder[2];
	if (m_source_greyalpha) {
		src_reorder[0] = src[0];
		src_reorder[1] = src[3];
		endpoints[0].buffer = src_reorder;
	}

	graphengine::BufferDescriptor dst_reorder[2];
	if (m_sink_greyalpha) {
		dst_reorder[0] = dst[0];
		dst_reorder[1] = dst[3];
		endpoints[1].buffer = dst_reorder;
	}

	try {
		m_graph->run(endpoints, tmp);
	} catch (const graphengine::Exception &e) {
		rethrow_graphengine_exception(e);
	}
}

} // namespace graph
} // namespace zimg
