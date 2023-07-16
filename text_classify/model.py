import numpy as np
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression

# 训练数据
texts = ["高兴", "傻逼", "tmd","呵呵", "嘿嘿"]
labels = [1, 0, 0, 1, 0]

# 特征提取
vectorizer = CountVectorizer()
X = vectorizer.fit_transform(texts)

print("X: {}".format(X))

# 划分训练集和测试集
X_train, X_test, y_train, y_test = train_test_split(X, labels, test_size=0.2, random_state=42)

# 训练分类模型
model = LogisticRegression()
model.fit(X_train, y_train)

# 预测
X_new = vectorizer.transform(["开心", "难过"])
predictions = model.predict(X_new)

# 输出预测结果
for text, prediction in zip(["开心", "难过"], predictions):
    if prediction == 1:
        print(f"{text} 是好的情绪文本")
    else:
        print(f"{text} 是坏的情绪文本")