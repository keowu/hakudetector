/***************************************************************************
 *                                                                         *
 *   Copyright (C) 2020 by Keowu                                           *
 *                                                                         *
 *   www.joaovitor.gq                                                      *
 *   www.github.com/keowu                                                  *
 *                                                                         *
 ***************************************************************************/
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

//form peheaderanaliser
#include <peheadervisualizer.h>

//form inject
#include <injecttools.h>

//get admin
#include <shlobj.h>

//hexedito
#include "QHexView.h"

//Cryptohash
#include <QCryptographicHash>

HANDLE hProcessSnap;
HANDLE hProcess = NULL;
PROCESSENTRY32 pe32;

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    constant.path = QDir::currentPath() + "/debug/haku.config";
    qDebug() << constant.path;
    if(constant.path.isEmpty()){
        qDebug() << "ERRO !";
    }else{
        qDebug() << "SUCESSO !";
        QFile hakuconfig(constant.path);
        if(hakuconfig.open(QIODevice::ReadOnly | QIODevice::Text)){
            QString virustotapi = hakuconfig.readLine();
            int inicio = virustotapi.indexOf("V");
            int fim = virustotapi.indexOf("=");
            constant.virustotAPI = virustotapi.replace(inicio, fim+1, "");
            qDebug() << "VIRUS TOTAL API KEY FROM CONFIG FILE = " << constant.virustotAPI;
        }else{
            qDebug() << "ERRO AO LER !";
        }
    }
}

MainWindow::~MainWindow()
{
    delete ui;
}


void MainWindow::on_pushButton_5_clicked()
{
    constant.path = QFileDialog::getOpenFileName(this, tr("Escolha o arquivo"), "/", tr("*(*.exe)"));
    if(constant.path == ""){
        QMessageBox::warning(this, "Cancelado !", "Você não selecionou nenhum arquivo.");
    }else{
        QMessageBox::warning(this, "Carregando !", "Espere alguns segundos enquanto preparamos tudo...");
    }

}

void MainWindow::on_pushButton_8_clicked()
{
    hProcessSnap = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 );
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

void MainWindow::on_pushButton_clicked()
{
    peheadervisualizer pehv;
    pehv.setWindowTitle("PE HEADER VISUALIZER");
    pehv.exec();
}

void MainWindow::on_pushButton_3_clicked()
{
    injecttools injecttool;
    injecttool.setWindowTitle("DLL Inject");
    injecttool.isUSERANDMIN(IsUserAnAdmin());
    injecttool.exec();
}

void MainWindow::on_pushButton_4_clicked()
{
    constant.path = QFileDialog::getOpenFileName(this, tr("Escolha o arquivo"), "/", tr("*"));
    if(constant.path.isEmpty()){
        QMessageBox::warning(this, "Cancelado !", "Você não selecionou nenhum arquivo.");
        return;
    }else{
        QMessageBox::warning(this, "Carregando !", "Espere alguns segundos enquanto preparamos tudo...");
    }
    QFile file_bytes(constant.path);
    file_bytes.open(QIODevice::ReadOnly | QIODevice::Text);

    QByteArray a = file_bytes.readAll();
    QHexView *phexView = new QHexView;
    phexView->setData(new QHexView::DataStorageArray(a));
    phexView->setWindowTitle("Hex Analyser");
    phexView->show();
}

void MainWindow::on_pushButton_6_clicked()
{
    constant.path = QFileDialog::getOpenFileName(this, tr("Escolha o arquivo"), "/", tr("*"));
    if(constant.path.isEmpty()){
        QMessageBox::warning(this, "Cancelado !", "Você não selecionou nenhum arquivo.");
        return;
    }else{
        QMessageBox::warning(this, "Carregando !", "Espere alguns segundos enquanto preparamos tudo...");
    }
    QFile file_analyse(constant.path);
    file_analyse.open(QIODevice::ReadOnly);
    QCryptographicHash hash(QCryptographicHash::Md5);
    if(hash.addData(&file_analyse)){
        qDebug() << "MD5 HASH: " << hash.result().toHex();
    }
}
