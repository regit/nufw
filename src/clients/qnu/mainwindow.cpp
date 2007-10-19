#include <QtGui>

#include "mainwindow.h"

#include "mainwindow.moc"

/*
 * See http://doc.trolltech.com/4.3/mainwindows-application.html
 */

MainWindow::MainWindow()
	: QMainWindow()
{
	createActions();
	createMenus();

	createToolBars();

	createStatusBar();

	createTrayIcon();

	resize(400, 300);
}

void MainWindow::createMenus()
{
	fileMenu = menuBar()->addMenu(tr("&File"));
	fileMenu->addAction(openAct);
	fileMenu->addAction(exitAct);

	menuBar()->addSeparator();
	helpMenu = menuBar()->addMenu(tr("&Help"));
	helpMenu->addAction(aboutQtAct);
}

void MainWindow::createActions()
{
	openAct = new QAction(QIcon(":/images/open.png"), tr("&Open..."), this);
	openAct->setShortcut(tr("Ctrl+O"));
	openAct->setStatusTip(tr("Open an existing file"));
	connect(openAct, SIGNAL(triggered()), this, SLOT(open()));

	exitAct = new QAction(tr("&Quit"), this);
	exitAct->setShortcut(tr("Ctrl+Q"));
	exitAct->setStatusTip(tr("Quit application"));
	connect(exitAct, SIGNAL(triggered()), qApp, SLOT(quit()));

	aboutQtAct = new QAction(tr("About &Qt"), this);
	aboutQtAct->setStatusTip(tr("Show the Qt library's About box"));
	connect(aboutQtAct, SIGNAL(triggered()), qApp, SLOT(aboutQt()));
}

void MainWindow::createToolBars()
{
	fileToolBar = addToolBar(tr("File"));
//	fileToolBar->addAction(newAct);
	fileToolBar->addAction(openAct);
//	fileToolBar->addAction(saveAct);
//
//	editToolBar = addToolBar(tr("Edit"));
//	editToolBar->addAction(cutAct);
//	editToolBar->addAction(copyAct);
//	editToolBar->addAction(pasteAct);
}

void MainWindow::createStatusBar()
{
	statusBar()->showMessage(tr("Ready"));
}

void MainWindow::createTrayIcon()
{
	if ( ! QSystemTrayIcon::isSystemTrayAvailable() ) {
	}

	trayIcon = new QSystemTrayIcon(this);
	trayIconMenu = new QMenu(this);
	trayIconMenu->addSeparator();
	trayIconMenu->addAction(exitAct);

	QIcon icon = QIcon(":/images/icon.png");
	trayIcon->setIcon(icon);

	trayIcon->show();
	trayIcon->setContextMenu(trayIconMenu);
}

void MainWindow::open()
{
//	if (maybeSave()) {
		QString fileName = QFileDialog::getOpenFileName(this);
		if (!fileName.isEmpty())
			;//loadFile(fileName);
//	}
}
