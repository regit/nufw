#include <iostream>

#include <QApplication>
//#include <QPushButton>
//#include <QGridLayout>

#include "mainwindow.h"

using std::cout;

int main(int argc, char **argv)
{
	QApplication app(argc, argv);

//	cout << "Hello, world !" << std::endl;
//
//	QWidget *window = new QWidget;
//	QGridLayout *layout = new QGridLayout;
//
//	QPushButton hello("Hello world!");
//	hello.resize(100,30);
//
//	layout->addWidget(&hello, 0, 0);
//
//	window->setLayout(layout);
//	window->show();

	MainWindow mainWin;

	mainWin.show();

	return app.exec();
}
