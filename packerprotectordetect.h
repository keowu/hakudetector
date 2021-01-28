#ifndef PACKERPROTECTORDETECT_H
#define PACKERPROTECTORDETECT_H

#include <QDialog>
#include <QDebug>
#include <QDir>

class PackerProtectDetect{

private:


    QByteArray getStrReadToByteArrayToCheck(QString leitura){
        int i = 0;
        leitura = leitura.split(' ', Qt::SkipEmptyParts).join("");
        QByteArray ByteSign;
        QString tmp;
        for(; i < leitura.size(); i+=2){
            if(leitura.at(i) == "?" && leitura.at(i+1) == "?"){
                ByteSign.append('\x00');
            }else{
                tmp.clear();
                tmp.append(i);
                tmp.append(i+1);
                ByteSign.append(QByteArray::fromHex(tmp.toLatin1()));
            }
        }
        //qDebug() << "Assinatura = " << ByteSign;
        return ByteSign;
    }

    QString getOffSetPaternOfFileAsByteArray(){
        QString path = QDir::currentPath() + "/debug/userdb.txt";
        if(path.isEmpty()){
            qDebug() << "ERRO ao carregar assinaturas";
            return 0;
        }
        QFile userDB(path);
        bool flag = userDB.open(QIODevice::ReadOnly | QIODevice::Text);
        if(!flag){
            qDebug() << "ERRO abrir arquivo";
            return 0;
        }

        while(!userDB.atEnd()){
            QString NomePackerOrProtector = userDB.readLine();
            //qDebug() << NomePackerOrProtector;
            QString Signature = userDB.readLine();
            QString EP = userDB.readLine();
            QString Tash = userDB.readLine();
            int inicioSignature = Signature.indexOf("s");
            int fimSignature = Signature.indexOf("=");
            Signature = Signature.replace(inicioSignature, fimSignature, "");
            QByteArray SignatureByteArray = this->getStrReadToByteArrayToCheck(Signature);
        }

        return 0;
    }


public:
    QString protectorAssignature(QByteArray a){
        QString ret = NULL;
        int i = 0;
        if(!(a.size() > 3)){
            qDebug() << "Image size not is better than 3";
            return ret;
        }

        while(i < a.length()){
            this->getOffSetPaternOfFileAsByteArray();

            i++;
        }

        return ret;
    }


};


#endif // PACKERPROTECTORDETECT_H
