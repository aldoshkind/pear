project(gstreamer)

file(GLOB SRCS "*.cpp")

add_executable(gstreamer ${SRCS})

target_link_libraries(gstreamer pear ${TARGET_LIBS} gstreamer-1.0 gobject-2.0 glib-2.0)
