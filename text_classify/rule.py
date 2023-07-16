text_dict = {
    "高兴": "好",
    "傻逼": "坏",
    "tmd": "坏"
}

def classify_text_emotion(text):
    if text in text_dict:
        return text_dict[text]
    else:
        return "未知"

# 示例文本
texts = ["高兴", "难过", "傻逼", "开心"]

for text in texts:
    result = classify_text_emotion(text)
    if result == "好":
        print(f"{text} 是好的情绪文本")
    elif result == "坏":
        print(f"{text} 是坏的情绪文本")
    else:
        print(f"{text} 的情绪无法确定")