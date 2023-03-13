cmake_minimum_required(VERSION 3.10)

project(gstreamer)

file(GLOB SRCS "*.cpp")

add_executable(gstreamer ${SRCS})

include_directories(${EXAMPLE_GST_LIB_DIR}/httplib/
					${EXAMPLE_GST_LIB_DIR}/base64/
					${EXAMPLE_GST_LIB_DIR}/json/single_include/nlohmann/
					)

target_link_libraries(gstreamer pear ${TARGET_LIBS} gstreamer-1.0 gobject-2.0 glib-2.0)
