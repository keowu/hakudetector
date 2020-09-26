#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <qfiledialog.h>
#include <qmessagebox.h>
#include "stdio.h"

#include <cstring>
#include <string.h>
#include <iostream>
#include <windows.h>
#include <conio.h>
#include <dos.h>
#include <tlhelp32.h>
#include <stdio.h>

//debug
#include <QtDebug>

#include <QMessageBox>

//process form
#include <processviewer.h>

//form analyses
#include <processanalyser.h>


//https://www.mpgh.net/forum/17-game-hacking-tutorials/7511-writing-your-own-c-trainer.html

QString path;
HANDLE hProcessSnap;	// will store a snapshot of all processes
HANDLE hProcess = NULL;	// we will use this one for the WarRock process
PROCESSENTRY32 pe32;	// stores basic info of a process, using this one to read the ProcessID from

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
}

MainWindow::~MainWindow()
{
    delete ui;
}


void MainWindow::on_pushButton_5_clicked()
{
    path = QFileDialog::getOpenFileName(this, tr("Escolha a mensagem"), "/", tr("Cs 1.6 binary(hl.exe)"));
    if(path == ""){
        QMessageBox::warning(this, "Cancelado !", "Você não selecionou nenhum arquivo.");
    }else{
        QMessageBox::warning(this, "Carregando !", "Espere alguns segundos enquanto preparamos tudo...");
    }

}

void MainWindow::on_pushButton_8_clicked()
{
    hProcessSnap = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 );	// Faz um snapshot do processo
    pe32.dwSize = sizeof( PROCESSENTRY32 );		// Tamanho correto
    do	// loop até encontrar o processo
        {
            QString processo = QString::fromWCharArray(pe32.szExeFile);
            if(processo == "explorer.exe")
            {
                qDebug() << "Encontrei" << processo;
                QMessageBox::critical(this, "Injected", "Finded");
                hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID);	// abre, assina ao hProcess handle
                break;	// Para o loop
            }
        }
        while(Process32Next(hProcessSnap, &pe32));

    CloseHandle( hProcessSnap );	// fecha o handle

        if(hProcess == NULL){
            QMessageBox::critical(this, "Erro", "Erro");
        }else{
            QMessageBox::warning(this, "Sucesso", "Sucesso com o handle !");
        }
        CloseHandle(hProcess);	// close the handle
}

void MainWindow::on_pushButton_9_clicked()
{
    ProcessViewer procview;
    qDebug() << "Form de processos abertos";
    procview.exec();
}

void MainWindow::on_pushButton_2_clicked()
{
    processanalyser procan;
    procan.setWindowTitle("Detect File Assignatures");
    procan.exec();
}
