#ifndef __MAIN_WINDOW__
#define __MAIN_WINDOW__

#include <QMainWindow>
#include <QSystemTrayIcon>

class MainWindow: public QMainWindow {
	Q_OBJECT

public:
	MainWindow();


private slots:
	void open();

private:
	void createMenus();
	void createActions();
	void createToolBars();
	void createStatusBar();
	void createTrayIcon();

	QMenu *fileMenu;
	QMenu *helpMenu;

	QToolBar *fileToolBar;
	QToolBar *editToolBar;

	QAction *openAct;
	QAction *exitAct;
	QAction *aboutQtAct;

	QSystemTrayIcon *trayIcon;
	QMenu *trayIconMenu;
};

#endif /* __MAIN_WINDOW__ */
