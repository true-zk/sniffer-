
// SnifferDlg.h: 头文件

#pragma once
#include"pcap.h"
#include"protocol.h"
#include"util.h"

// CSnifferDlg 对话框
class CSnifferDlg : public CDialogEx
{
// 构造
public:
	CSnifferDlg(CWnd* pParent = nullptr);	// 标准构造函数

	/* 实现功能funcs */
	bool initCap(); //初始化
	int start(); //开始抓包
	int updateTree(int index);
	int updateEdit(int index);
	int savefile();
	int readfile(CString fpath);
	bool iprecombine(int index);//重组
	int updateTree1(pkt_T *pakeage_T, int len); //展示重组树
	int updateEdit1(int len, u_char* pkt_data); //展示重组详细
	bool search(u_char* str);

	/* data */
	char errbuf[PCAP_ERRBUF_SIZE];//内置errorbuf
	int n_dev;				//网卡数
	pcap_if_t* alldev;		//所有网卡
	pcap_if_t* dev;			//选定的网卡
	pcap_t* handle; //pcap 创建的【捕获句柄】
	CString filter;			//filter
	int n_pkt;				    //抓包数
	struct pktcount pkcount_T;	// 各类包计数结构体

	pcap_dumper_t* myfile;//存储的文件
	char filepath[512];
	char filename[512];

	CPtrList pk_list;			//抓包链表
	CPtrList m_localDataList;	//pkt_T链表，存储规范化网络包
	CPtrList m_netDataList;		//char*链表，存储网络包数据

	HANDLE m_threadhandle; //线程

///////////////////////////////////////////////////////
// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_SNIFFER_DIALOG };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持


// 实现
protected:
	HICON m_hIcon;

	// 生成的消息映射函数
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()

private:
	int cursor_index = -1;
public:
	//各控件
	CListCtrl m_listCtrl; //包列表
	CComboBox m_comboBox;//网卡选择控件
	CTreeCtrl m_treeCtrl;//包解析
	CEdit m_edit;		//包详细
	CButton m_buttonStart;	//开始按钮
	CButton m_buttonStop;	//结束
	CButton m_buttonSave;
	CButton m_buttonRead;
	CButton m_buttonrecombine;
	
	//触发函数
	afx_msg void OnBnClickedButton1();//开始
	afx_msg void OnBnClickedButton2();//结束
	afx_msg void OnBnClickedButton3();//保存
	afx_msg void OnBnClickedButton4();//读包
	afx_msg void OnLvnItemchangedList2(NMHDR* pNMHDR, LRESULT* pResult);//包列表
	afx_msg void OnNMCustomdrawList2(NMHDR* pNMHDR, LRESULT* pResult);//染色
	afx_msg void OnBnClickedButton5();//filter set
	afx_msg void OnBnClickedButton6();
};
