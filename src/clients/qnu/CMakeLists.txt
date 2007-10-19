PROJECT(tray-app)

# apt-get install libqt4-dev
INCLUDE(FindQt4)

IF (NOT QT4_FOUND)
	MESSAGE(FATAL_ERROR "Qt4 development files not found. Please install libqt4-dev")
ENDIF (NOT QT4_FOUND)

INCLUDE(${QT_USE_FILE})

ADD_DEFINITIONS(${QT_DEFINITIONS})
INCLUDE_DIRECTORIES(${CMAKE_CURRENT_BINARY_DIR} ${QT_INCLUDE_DIR} ${QT_QTGUI_INCLUDE_DIR})
LINK_DIRECTORIES(${QT_LIBRARY_DIR})

SET(GUI_SRCS
	mainwindow.cpp
	)

SET(GUI_HDRS
	mainwindow.h
	)

# there's a typo in cmake documentation: QT4_ADD_RESOURCES (with an S)
QT4_ADD_RESOURCES(GUI_SRCS application.qrc)

# for this to work, $name.cpp file must include $name.moc
QT4_AUTOMOC( ${GUI_SRCS} )

ADD_EXECUTABLE(tray-app
	main.cpp
	${GUI_SRCS}
	${GUI_HDRS}
	)

#QT4_GENERATE_MOC(${CMAKE_CURRENT_SOURCE_DIR}/mainwindow.h ${CMAKE_CURRENT_BINARY_DIR}/moc_mainwindow.cpp)
##QT4_AUTOMOC(${GUI_HDRS)

TARGET_LINK_LIBRARIES(tray-app ${QT_QTCORE_LIBRARY} ${QT_QTGUI_LIBRARY})
