#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>


QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:

    void on_btnFileDetect_clicked();

    void on_btnInjectTool_clicked();

    void on_btnVirusTotal_clicked();

    void on_btnPEHeadVisualizer_clicked();

    void on_btnHexEditor_clicked();

    void on_btnOpenDll_clicked();

    void on_btnInjectLoadedDllInHaku_clicked();

    void on_btnProcessGerencia_clicked();

private:
    typedef struct{
        QString virustotAPI;
        QString path;
    }constantes;

    constantes constant;

    Ui::MainWindow *ui;
};
#endif // MAINWINDOW_H
