package oss

import (
	"context"
	"log"
	"os"
	"snoop/utils"

	"github.com/aliyun/alibabacloud-oss-go-sdk-v2/oss"
	"github.com/aliyun/alibabacloud-oss-go-sdk-v2/oss/credentials"
)

// 定义全局变量
const (
	DefaultRegion     string = "cn-shanghai-internal" // 存储区域
	DefaultBucketName string = "nc-agent-file-baba"   // 存储空间名称
	OSSAccessKey      string = "2+Ij+aBFC+wwJLBYVlMaQhlrTb2z3TE0Y4FzwCLVt48="
	OSSAccessSecret   string = "O5tKsh9B8XjakTVy04FHHk+QsuEAK+acgWrUClyxC6k="
)

type OSSStorage struct {
	region string //oss 存储所在的地域
	client *oss.Client
}

// 设置oss的AK和SK
func init() {
	os.Setenv("OSS_ACCESS_KEY_ID", utils.AesDecryptByECB(OSSAccessKey, utils.CustomKey))
	os.Setenv("OSS_ACCESS_KEY_SECRET", utils.AesDecryptByECB(OSSAccessSecret, utils.CustomKey))
}

var ossClient = NewOSSStorage(DefaultRegion)

func NewOSSStorage(region string) *OSSStorage {
	if region == "" {
		region = DefaultRegion
	}
	return &OSSStorage{
		region: "cn-shanghai",
		client: oss.NewClient(oss.LoadDefaultConfig().
			WithCredentialsProvider(credentials.NewEnvironmentVariableCredentialsProvider()).
			WithRegion(region)),
	}
}

// 文件上传到OSS，上传之前会判断文件是否存在。
// 需要提供文件绝对路径
func PutOSSObject(bucket, filepath, objName string) {
	// 检查bucket名称是否为空
	if len(bucket) == 0 {
		log.Fatalf("invalid parameters, bucket name required")
	}

	// 检查object名称是否为空
	if len(objName) == 0 {
		log.Fatalf("invalid parameters, object name required")
	}

	if ok, _ := ossClient.client.IsObjectExist(context.TODO(), bucket, objName); ok { // 文件已经存在
		//log.Printf("%s already exist.", objName)
		return
	}

	// 创建上传对象的请求
	request := &oss.PutObjectRequest{
		Bucket: oss.Ptr(bucket),  // 存储空间名称
		Key:    oss.Ptr(objName), // 对象名称
	}

	// 执行上传对象的请求
	_, err := ossClient.client.PutObjectFromFile(context.TODO(), request, filepath)
	if err != nil {
		log.Fatalf("failed to put %s object %v", filepath, err)
	}

}
