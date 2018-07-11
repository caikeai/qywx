hexo generate
cp -R public/* .deploy/caikeai.github.io
cd .deploy/caikeai.github.io
git add .
git commit -m “update”
git push origin master
